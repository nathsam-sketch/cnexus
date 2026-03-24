"""
╔══════════════════════════════════════════════════════════════════╗
║                      NEXUS BOT  v2.0                            ║
║            OSINT & Alt-Detection Intelligence Bot               ║
╚══════════════════════════════════════════════════════════════════╝

Commands:
  /roblox_lookup   - Deep OSINT profile on a Roblox user
  /compare_roblox  - Compare two Roblox accounts for alt signals
  /compare_discord - Compare two Discord accounts for alt signals
  /flag            - Flag a Roblox user as a person of interest
  /flags           - List all flagged users
  /unflag          - Remove a flag
  /key_manage      - Manage auth keys (owner key only)
  /logout          - End your session
  /export          - Export last report as a PDF

Setup:
  1. pip install "discord.py[voice]" aiohttp Pillow reportlab imagehash
  2. Set BOT_TOKEN and OWNER_KEY below
  3. python bot.py
"""

# ─────────────────────────────────────────────────────
#  IMPORTS
# ─────────────────────────────────────────────────────
import discord
from discord import app_commands, ui
from discord.ext import commands

import aiohttp
import asyncio
import difflib
import hashlib
import io
import re
import sqlite3
import time
from datetime import datetime, timezone
from typing import Optional, List

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable, Paragraph, SimpleDocTemplate,
    Spacer, Table, TableStyle,
)

try:
    import imagehash
    from PIL import Image
    IMAGE_HASH_AVAILABLE = True
except ImportError:
    IMAGE_HASH_AVAILABLE = False

# ─────────────────────────────────────────────────────
#  CONFIG
# ─────────────────────────────────────────────────────
import os
BOT_TOKEN   = os.getenv("BOT_TOKEN", "")
OWNER_KEY   = os.getenv("OWNER_KEY", "")
DB_PATH     = "nexus.db"
SESSION_TTL = 6 * 3600

# ─────────────────────────────────────────────────────
#  DATABASE
# ─────────────────────────────────────────────────────
def db_init():
    con = sqlite3.connect(DB_PATH)
    con.executescript("""
        CREATE TABLE IF NOT EXISTS auth_keys (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            label   TEXT    NOT NULL,
            value   TEXT    NOT NULL UNIQUE,
            created INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            user_id  TEXT PRIMARY KEY,
            key_used TEXT NOT NULL,
            expires  INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS flags (
            roblox_id  TEXT PRIMARY KEY,
            username   TEXT NOT NULL,
            reason     TEXT NOT NULL,
            flagged_by TEXT NOT NULL,
            flagged_at INTEGER NOT NULL
        );
    """)
    con.commit()
    con.close()

def db():
    return sqlite3.connect(DB_PATH)

# ─────────────────────────────────────────────────────
#  AUTH
# ─────────────────────────────────────────────────────
def validate_key(key: str) -> bool:
    if key == OWNER_KEY:
        return True
    with db() as con:
        return con.execute(
            "SELECT 1 FROM auth_keys WHERE value=?", (key,)
        ).fetchone() is not None

def is_owner_key(key: str) -> bool:
    return key == OWNER_KEY

def get_session(user_id) -> Optional[str]:
    with db() as con:
        row = con.execute(
            "SELECT key_used, expires FROM sessions WHERE user_id=?",
            (str(user_id),)
        ).fetchone()
    if row and row[1] > int(time.time()):
        return row[0]
    return None

def create_session(user_id, key: str):
    with db() as con:
        con.execute(
            "INSERT OR REPLACE INTO sessions VALUES (?,?,?)",
            (str(user_id), key, int(time.time()) + SESSION_TTL)
        )

def destroy_session(user_id):
    with db() as con:
        con.execute("DELETE FROM sessions WHERE user_id=?", (str(user_id),))

# ─────────────────────────────────────────────────────
#  AUTH MODAL
# ─────────────────────────────────────────────────────
class AuthModal(ui.Modal, title="Nexus — Authentication"):
    key_input = ui.TextInput(
        label="Access Key",
        placeholder="Enter your Nexus access key...",
        style=discord.TextStyle.short,
        required=True,
        min_length=1,
        max_length=128,
    )

    def __init__(self, callback):
        super().__init__()
        self._cb = callback

    async def on_submit(self, interaction: discord.Interaction):
        key = self.key_input.value.strip()
        if not validate_key(key):
            await interaction.response.send_message(
                embed=err_embed("Invalid access key."), ephemeral=True
            )
            return
        create_session(interaction.user.id, key)
        # Acknowledge the modal immediately, then run the callback
        await interaction.response.send_message(
            embed=nexus_embed("✅ Authenticated", "Session started. Running your command...", SLATE)
        )
        await self._cb(interaction, key)

# ─────────────────────────────────────────────────────
#  ROBLOX API
# ─────────────────────────────────────────────────────
RBX_H = {"Accept": "application/json"}

async def rbx_get(s: aiohttp.ClientSession, url: str) -> dict:
    try:
        async with s.get(url, headers=RBX_H,
                         timeout=aiohttp.ClientTimeout(total=12)) as r:
            if r.status == 200:
                return await r.json()
    except Exception:
        pass
    return {}

async def rbx_post(s: aiohttp.ClientSession, url: str, payload: dict) -> dict:
    try:
        async with s.post(url, json=payload, headers=RBX_H,
                          timeout=aiohttp.ClientTimeout(total=12)) as r:
            if r.status == 200:
                return await r.json()
    except Exception:
        pass
    return {}

async def resolve_username(s: aiohttp.ClientSession, username: str) -> dict:
    j = await rbx_post(s, "https://users.roblox.com/v1/usernames/users",
                       {"usernames": [username], "excludeBannedUsers": False})
    if j.get("data"):
        u = j["data"][0]
        return {"id": u["id"], "username": u["name"]}
    return {}

async def fetch_deep_profile(s: aiohttp.ClientSession, uid: int) -> dict:
    """Fetch all profile data concurrently — each call has an 8s timeout."""
    uid_s = str(uid)

    async def safe(coro):
        try:
            return await asyncio.wait_for(coro, timeout=8)
        except Exception:
            return {}

    (
        profile, thumb, bust, av_info,
        fc, folc, fwc, fl,
        grp, bdg, gms, pres,
        hist, inv, vc,
    ) = await asyncio.gather(
        safe(rbx_get(s, f"https://users.roblox.com/v1/users/{uid_s}")),
        safe(rbx_get(s, f"https://thumbnails.roblox.com/v1/users/avatar?userIds={uid_s}&size=420x420&format=Png")),
        safe(rbx_get(s, f"https://thumbnails.roblox.com/v1/users/avatar-bust?userIds={uid_s}&size=420x420&format=Png")),
        safe(rbx_get(s, f"https://avatar.roblox.com/v1/users/{uid_s}/avatar")),
        safe(rbx_get(s, f"https://friends.roblox.com/v1/users/{uid_s}/friends/count")),
        safe(rbx_get(s, f"https://friends.roblox.com/v1/users/{uid_s}/followers/count")),
        safe(rbx_get(s, f"https://friends.roblox.com/v1/users/{uid_s}/followings/count")),
        safe(rbx_get(s, f"https://friends.roblox.com/v1/users/{uid_s}/friends?limit=50")),
        safe(rbx_get(s, f"https://groups.roblox.com/v1/users/{uid_s}/groups/roles")),
        safe(rbx_get(s, f"https://badges.roblox.com/v1/users/{uid_s}/badges?limit=50&sortOrder=Desc")),
        safe(rbx_get(s, f"https://games.roblox.com/v1/users/{uid_s}/games?accessFilter=Public&limit=10&sortOrder=Asc")),
        safe(rbx_post(s, "https://presence.roblox.com/v1/presence/users", {"userIds": [uid]})),
        safe(rbx_get(s, f"https://users.roblox.com/v1/users/{uid_s}/username-history?limit=20&sortOrder=Asc")),
        safe(rbx_get(s, f"https://inventory.roblox.com/v1/users/{uid_s}/assets/collectibles?limit=25&sortOrder=Desc")),
        safe(rbx_get(s, f"https://voice.roblox.com/v1/settings/user/{uid_s}")),
    )

    presence = pres.get("userPresences", [{}])[0] if pres.get("userPresences") else {}

    return {
        "profile":         profile,
        "avatar_url":      (thumb.get("data") or [{}])[0].get("imageUrl", ""),
        "bust_url":        (bust.get("data")  or [{}])[0].get("imageUrl", ""),
        "avatar_info":     av_info,
        "friends_count":   fc.get("count", 0),
        "followers_count": folc.get("count", 0),
        "following_count": fwc.get("count", 0),
        "friends":         fl.get("data", []),
        "groups":          grp.get("data", []),
        "badges":          bdg.get("data", []),
        "games":           gms.get("data", []),
        "presence":        presence,
        "prev_usernames":  [n["name"] for n in hist.get("data", [])],
        "collectibles":    inv.get("data", []),
        "voice_enabled":   vc.get("isVoiceEnabled", None),
        "last_online":     presence.get("lastOnline", "") or profile.get("lastOnline", ""),
    }

# ─────────────────────────────────────────────────────
#  AVATAR HASH
# ─────────────────────────────────────────────────────
async def fetch_avatar_hash(s: aiohttp.ClientSession, url: str) -> Optional[str]:
    if not url:
        return None
    try:
        async with s.get(url, timeout=aiohttp.ClientTimeout(total=10)) as r:
            if r.status == 200:
                data = await r.read()
                if IMAGE_HASH_AVAILABLE:
                    img = Image.open(io.BytesIO(data))
                    return str(imagehash.phash(img))
                return hashlib.md5(data).hexdigest()
    except Exception:
        pass
    return None

def hash_sim(h1: str, h2: str) -> float:
    if not h1 or not h2:
        return 0.0
    if IMAGE_HASH_AVAILABLE:
        try:
            d = imagehash.hex_to_hash(h1) - imagehash.hex_to_hash(h2)
            return max(0.0, 1.0 - d / 64.0)
        except Exception:
            pass
    return 1.0 if h1 == h2 else 0.0

# ─────────────────────────────────────────────────────
#  TEXT SIMILARITY
# ─────────────────────────────────────────────────────
def text_sim(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a.lower(), b.lower()).ratio()

def username_sim(a: str, b: str) -> float:
    base_a = re.sub(r"\d+$", "", a.lower())
    base_b = re.sub(r"\d+$", "", b.lower())
    return max(text_sim(a, b), text_sim(base_a, base_b) if base_a and base_b else 0.0)

# ─────────────────────────────────────────────────────
#  SCORE BAR
# ─────────────────────────────────────────────────────
def score_bar(score: int) -> str:
    filled = round(score / 100 * 12)
    return f"`{'█' * filled}{'░' * (12 - filled)}` **{score}/100**"

# ─────────────────────────────────────────────────────
#  DEEP PROFILE ANALYSIS
# ─────────────────────────────────────────────────────
def analyse_profile(R: dict) -> dict:
    prof    = R.get("profile", {})
    groups  = R.get("groups", [])
    badges  = R.get("badges", [])
    games   = R.get("games", [])
    av_info = R.get("avatar_info", {})
    friends = R.get("friends", [])
    collect = R.get("collectibles", [])
    prev    = R.get("prev_usernames", [])
    now     = datetime.now(timezone.utc)
    flags   = []
    analyst = []

    # Maturity (account age)
    created_raw = prof.get("created", "")
    age_days = 0
    created_str = "Unknown"
    if created_raw:
        try:
            dt = datetime.fromisoformat(created_raw.replace("Z", "+00:00"))
            age_days = (now - dt).days
            created_str = dt.strftime("%B %d, %Y")
        except Exception:
            pass
    maturity = min(100, int((age_days / 3650) * 100))

    # Social
    fc   = R.get("friends_count", 0)
    folc = R.get("followers_count", 0)
    fwc  = R.get("following_count", 0)
    social_size  = fc + folc + fwc
    social_score = min(100, int((social_size / 5000) * 100))
    social_notes = []
    if fc == 0 and folc == 0:
        social_notes.append("Zero social connections — isolation signal")
        flags.append("Zero friends/followers (possible alt)")
    if fwc > 0 and folc > 0:
        ff_r = round(folc / fwc, 2)
        if ff_r < 0.05:
            social_notes.append(f"Very low follower/following ratio ({ff_r})")
            flags.append(f"Possible follow-farming (ratio {ff_r})")
    if not social_notes:
        social_notes.append("No major social anomalies detected")

    # Activity
    badge_count    = len(badges)
    game_count     = len(games)
    activity_score = min(100, int(((badge_count / 100) * 70) + ((game_count / 10) * 30)))

    # Badge buckets
    buckets = {"0-7d": 0, "8-30d": 0, "31-90d": 0, "91-365d": 0, "366+d": 0, "unknown": 0}
    last_badge = "None"
    if badges:
        last_badge = badges[0].get("name", "Unknown")
    for b in badges:
        raw = b.get("awardedDate", "") or ""
        try:
            bdt  = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
            diff = (now - bdt).days
            if   diff <=  7: buckets["0-7d"]    += 1
            elif diff <= 30: buckets["8-30d"]   += 1
            elif diff <= 90: buckets["31-90d"]  += 1
            elif diff <= 365:buckets["91-365d"] += 1
            else:            buckets["366+d"]   += 1
        except Exception:
            buckets["unknown"] += 1

    # Avatar
    av_assets     = av_info.get("assets", [])
    asset_count   = len(av_assets)
    body_colors   = av_info.get("bodyColors", {})
    scales        = av_info.get("scales", {})
    av_type       = av_info.get("playerAvatarType", "R6")
    color_vals    = list(body_colors.values()) if body_colors else []
    unique_colors = len(set(color_vals))
    non_default_s = sum(1 for v in scales.values() if abs(float(v) - 1.0) > 0.01) if scales else 0
    av_fp_str     = hashlib.md5(
        (str(sorted(color_vals)) + str(sorted(a.get("id",0) for a in av_assets))).encode()
    ).hexdigest()[:10]
    av_score      = min(100, (asset_count * 5) + (unique_colors * 8) + (non_default_s * 10))
    if av_score < 30:
        flags.append("Low avatar customization (possible alt)")
    if unique_colors == 1 and color_vals:
        flags.append("All body parts same color — default avatar")

    # Groups
    total_groups  = len(groups)
    high_rank     = sum(1 for g in groups if g.get("role",{}).get("rank",0) >= 200)
    owner_rank    = sum(1 for g in groups if g.get("role",{}).get("rank",0) == 255)
    group_sizes   = [g.get("group",{}).get("memberCount",0) for g in groups]
    small_groups  = sum(1 for s in group_sizes[:10] if 0 < s <= 1000)
    avg_members   = int(sum(group_sizes[:10]) / max(len(group_sizes[:10]),1))
    group_score   = min(100, (total_groups * 5) + (high_rank * 15) + (owner_rank * 20))
    if owner_rank > 0:
        analyst.append(f"Owns or co-owns {owner_rank} group(s) — notable authority.")
    if small_groups > 3:
        flags.append(f"Member of {small_groups} small groups — alt cluster risk")

    # Economy
    rap_total     = sum(c.get("recentAveragePrice",0) for c in collect)
    limited_count = len(collect)

    # Overall
    overall = int(maturity*0.25 + social_score*0.20 + activity_score*0.20 +
                  av_score*0.15 + group_score*0.20)

    # Analyst text
    if age_days > 1825:
        analyst.append("Older account age supports legitimacy.")
    elif age_days < 90:
        analyst.append("Very new account — elevated suspicion.")
        flags.append("Account under 90 days old")
    else:
        analyst.append("Account age is moderate.")
    if badge_count >= 50:
        analyst.append("High badge count indicates active gameplay.")
    elif badge_count == 0:
        analyst.append("Zero badges — may never have played games.")
        flags.append("Zero badges earned")
    if limited_count > 0:
        analyst.append(f"Holds {limited_count} limited(s) (RAP {rap_total:,}).")
    if len(prev) >= 3:
        analyst.append(f"Frequent username changes ({len(prev)}) — identity shifting.")
        flags.append(f"{len(prev)} previous usernames — possible identity cycling")
    scores = [maturity, social_score, activity_score, av_score, group_score]
    if sum(1 for s in scores if s >= 60) >= 3:
        analyst.append("Strong across multiple dimensions.")
    elif sum(1 for s in scores if s < 30) >= 2:
        analyst.append("Mixed signals; some strengths, some gaps.")
    if flags:
        analyst.append(f"Key flags: {', '.join(f.replace('⚠️ ','') for f in flags[:3])}")

    return {
        "overall": overall, "maturity": maturity, "social": social_score,
        "activity": activity_score, "avatar_custom": av_score,
        "group_footprint": group_score, "age_days": age_days,
        "created_str": created_str, "social_size": social_size,
        "total_groups": total_groups, "high_rank": high_rank,
        "owner_rank": owner_rank, "avg_members_top": avg_members,
        "small_groups": small_groups, "asset_count": asset_count,
        "av_fp": av_fp_str, "av_type": av_type, "av_score": av_score,
        "color_ids": body_colors, "scales": scales, "last_badge": last_badge,
        "badge_buckets": buckets, "badge_count": badge_count,
        "game_count": game_count, "rap_total": rap_total,
        "limited_count": limited_count, "social_notes": social_notes,
        "flags": flags, "analyst": " ".join(analyst) or "No notable signals.",
        "unique_colors": unique_colors,
    }

# ─────────────────────────────────────────────────────
#  ROBLOX ALT ANALYSIS
# ─────────────────────────────────────────────────────
def analyse_alts_roblox(p1: dict, p2: dict) -> dict:
    signals = []; score = 0
    pr1 = p1.get("profile",{}); pr2 = p2.get("profile",{})

    us = username_sim(pr1.get("name",""), pr2.get("name",""))
    if us > 0.80: signals.append(f"🔴 Usernames highly similar ({us:.0%})"); score += 25
    elif us > 0.50: signals.append(f"🟡 Usernames moderately similar ({us:.0%})"); score += 10

    b1 = pr1.get("description","").strip(); b2 = pr2.get("description","").strip()
    if b1 and b2:
        bs = text_sim(b1, b2)
        if bs > 0.75: signals.append(f"🔴 Bios nearly identical ({bs:.0%})"); score += 20
        elif bs > 0.40: signals.append(f"🟡 Bios share notable overlap ({bs:.0%})"); score += 8

    c1 = pr1.get("created",""); c2 = pr2.get("created","")
    if c1 and c2:
        try:
            d1 = datetime.fromisoformat(c1.replace("Z","+00:00"))
            d2 = datetime.fromisoformat(c2.replace("Z","+00:00"))
            gap = abs((d1-d2).days)
            if gap < 7: signals.append(f"🔴 Created within {gap} day(s) of each other"); score += 20
            elif gap < 30: signals.append(f"🟡 Created within {gap} days of each other"); score += 10
        except Exception: pass

    g1 = {g["group"]["id"] for g in p1.get("groups",[]) if "group" in g}
    g2 = {g["group"]["id"] for g in p2.get("groups",[]) if "group" in g}
    sg = g1 & g2
    if sg:
        pct = len(sg)/max(len(g1|g2),1)
        if pct > 0.5: signals.append(f"🔴 {len(sg)} shared groups ({pct:.0%} overlap)"); score += 20
        elif len(sg) >= 3: signals.append(f"🟡 {len(sg)} shared groups"); score += 10
        else: signals.append(f"⚪ {len(sg)} shared group(s)"); score += 3

    r1 = {g["group"]["id"]: g.get("role",{}).get("rank",0) for g in p1.get("groups",[]) if "group" in g}
    r2 = {g["group"]["id"]: g.get("role",{}).get("rank",0) for g in p2.get("groups",[]) if "group" in g}
    same_rank = {gid for gid in sg if r1.get(gid) == r2.get(gid)}
    if same_rank: signals.append(f"🟡 {len(same_rank)} shared group(s) with identical role rank"); score += 8

    f1 = {f["id"] for f in p1.get("friends",[])}; f2 = {f["id"] for f in p2.get("friends",[])}
    sf = f1 & f2
    if sf:
        pct = len(sf)/max(len(f1|f2),1)
        if pct > 0.3: signals.append(f"🔴 {len(sf)} mutual friends ({pct:.0%} overlap)"); score += 20
        else: signals.append(f"🟡 {len(sf)} mutual friend(s)"); score += 5

    bd1 = {b["id"] for b in p1.get("badges",[])}; bd2 = {b["id"] for b in p2.get("badges",[])}
    sb  = bd1 & bd2
    if sb:
        pct = len(sb)/max(len(bd1|bd2),1)
        if pct > 0.4: signals.append(f"🔴 {len(sb)} identical badges ({pct:.0%} overlap)"); score += 20
        elif len(sb) >= 5: signals.append(f"🟡 {len(sb)} shared badges"); score += 8

    av1 = p1.get("_av_fp"); av2 = p2.get("_av_fp")
    if av1 and av2 and av1 == av2:
        signals.append("🔴 Identical avatar fingerprint — same body color IDs"); score += 25

    h1 = p1.get("_av_hash"); h2 = p2.get("_av_hash")
    if h1 and h2:
        sim = hash_sim(h1, h2)
        if sim > 0.90: signals.append(f"🔴 Avatar images nearly identical ({sim:.0%})"); score += 25
        elif sim > 0.60: signals.append(f"🟡 Avatar images visually similar ({sim:.0%})"); score += 10

    score = min(score, 100)
    if score >= 70: verdict = "🔴 HIGH LIKELIHOOD — Strong alt signals"
    elif score >= 40: verdict = "🟡 MODERATE — Notable overlap, investigate further"
    elif score >= 15: verdict = "🟢 LOW — Minor similarities, likely coincidental"
    else: verdict = "✅ MINIMAL — No significant alt signals"

    return {"signals": signals, "score": score, "verdict": verdict,
            "shared_groups": len(sg), "shared_friends": len(sf), "shared_badges": len(sb)}

# ─────────────────────────────────────────────────────
#  DISCORD ALT ANALYSIS
# ─────────────────────────────────────────────────────
def analyse_alts_discord(m1, m2, mutual_guilds) -> dict:
    signals = []; score = 0
    now = datetime.now(timezone.utc)
    c1 = m1.created_at; c2 = m2.created_at

    gap = abs((c1-c2).days)
    if gap < 3: signals.append(f"🔴 Created within {gap} day(s) of each other"); score += 25
    elif gap < 14: signals.append(f"🟡 Created within {gap} days"); score += 10

    us = username_sim(m1.name, m2.name)
    if us > 0.80: signals.append(f"🔴 Usernames very similar ({us:.0%})"); score += 25
    elif us > 0.50: signals.append(f"🟡 Usernames moderately similar ({us:.0%})"); score += 10

    dn1 = getattr(m1,"display_name",m1.name); dn2 = getattr(m2,"display_name",m2.name)
    ds = text_sim(dn1, dn2)
    if ds > 0.80 and dn1 != m1.name: signals.append(f"🟡 Display names similar ({ds:.0%})"); score += 8

    if mutual_guilds:
        signals.append(f"🟡 {len(mutual_guilds)} mutual server(s): {', '.join(g.name for g in mutual_guilds[:4])}")
        score += min(len(mutual_guilds)*5, 20)

    av1 = str(m1.avatar.key) if m1.avatar else None
    av2 = str(m2.avatar.key) if m2.avatar else None
    if av1 and av2:
        if av1 == av2: signals.append("🔴 Identical avatar hash on both accounts"); score += 30
        else: signals.append("⚪ Avatars differ")

    bio1 = getattr(m1,"bio",None) or ""; bio2 = getattr(m2,"bio",None) or ""
    if bio1 and bio2:
        bs = text_sim(bio1, bio2)
        if bs > 0.75: signals.append(f"🔴 Bios nearly identical ({bs:.0%})"); score += 20
        elif bs > 0.40: signals.append(f"🟡 Bios overlap ({bs:.0%})"); score += 8

    age1 = (now-c1).days; age2 = (now-c2).days
    if age1 < 30 or age2 < 30:
        signals.append(f"🟡 At least one account under 30 days old ({age1}d / {age2}d)"); score += 10

    score = min(score, 100)
    if score >= 70: verdict = "🔴 HIGH LIKELIHOOD — Strong alt signals"
    elif score >= 40: verdict = "🟡 MODERATE — Notable overlap"
    elif score >= 15: verdict = "🟢 LOW — Minor similarities"
    else: verdict = "✅ MINIMAL — No significant signals"
    return {"signals": signals, "score": score, "verdict": verdict}

# ─────────────────────────────────────────────────────
#  REPORT STORE
# ─────────────────────────────────────────────────────
_reports: dict = {}

def store_report(uid, report: dict):
    _reports[str(uid)] = report

def get_report(uid) -> Optional[dict]:
    return _reports.get(str(uid))

# ─────────────────────────────────────────────────────
#  EMBED HELPERS
# ─────────────────────────────────────────────────────
BLUE   = 0x2b6cb0
TEAL   = 0x2c7a7b
GREEN  = 0x276749
RED    = 0x9b2c2c
GOLD   = 0xb7791f
PURPLE = 0x553c9a
SLATE  = 0x2d3748

def nexus_embed(title: str, desc: str = "", color: int = BLUE) -> discord.Embed:
    e = discord.Embed(title=title, description=desc or None, color=color)
    e.set_footer(text="Nexus • OSINT")
    return e

def err_embed(msg: str) -> discord.Embed:
    return nexus_embed("Error", msg, RED)

# ─────────────────────────────────────────────────────
#  PAGINATED VIEW
# ─────────────────────────────────────────────────────
class PageView(ui.View):
    def __init__(self, pages: List[discord.Embed]):
        super().__init__(timeout=300)
        self.pages = pages; self.current = 0
        self._sync()

    def _sync(self):
        self.prev_btn.disabled = self.current == 0
        self.next_btn.disabled = self.current >= len(self.pages) - 1
        for i, p in enumerate(self.pages):
            p.set_footer(text=f"Nexus • OSINT  —  Page {i+1}/{len(self.pages)}")

    @ui.button(label="◀", style=discord.ButtonStyle.secondary)
    async def prev_btn(self, interaction: discord.Interaction, _: ui.Button):
        self.current -= 1; self._sync()
        await interaction.response.edit_message(embed=self.pages[self.current], view=self)

    @ui.button(label="▶", style=discord.ButtonStyle.secondary)
    async def next_btn(self, interaction: discord.Interaction, _: ui.Button):
        self.current += 1; self._sync()
        await interaction.response.edit_message(embed=self.pages[self.current], view=self)

# ─────────────────────────────────────────────────────
#  BOT + SEND HELPER
# ─────────────────────────────────────────────────────
intents = discord.Intents.default()
intents.members = True
intents.message_content = True
bot  = commands.Bot(command_prefix="!", intents=intents)
tree = bot.tree

# Allow commands to run in guilds, DMs, and private channels (user-installable app)
_guild_ctx   = discord.app_commands.AppCommandContext(guild=True, dm_channel=True, private_channel=True)
_user_install = discord.app_commands.AppInstallationType(guild=True, user=True)
tree.allowed_contexts  = _guild_ctx
tree.allowed_installs  = _user_install

async def send(interaction: discord.Interaction, **kwargs):
    """Send a response that works in guilds, DMs, and GCs."""
    try:
        if interaction.response.is_done():
            await interaction.followup.send(**kwargs)
        else:
            await interaction.response.send_message(**kwargs)
    except Exception as e:
        print(f"[send error] {e}")

async def edit_original(interaction: discord.Interaction, **kwargs):
    """Edit the original response message."""
    try:
        await interaction.edit_original_response(**kwargs)
    except Exception as e:
        print(f"[edit error] {e}")

async def thinking_msg(interaction: discord.Interaction, text: str) -> None:
    """Send an immediate visible response, works everywhere including DMs."""
    await interaction.response.send_message(
        embed=nexus_embed("⏳ " + text, color=SLATE)
    )

# ─────────────────────────────────────────────────────
#  /roblox_lookup
# ─────────────────────────────────────────────────────
@tree.command(name="roblox_lookup", description="Deep OSINT intelligence profile on a Roblox user")
@app_commands.describe(username="Roblox username")
async def roblox_lookup(interaction: discord.Interaction, username: str):
    if not get_session(interaction.user.id):
        await interaction.response.send_modal(AuthModal(lambda i, k: _rlookup(i, username)))
        return
    await thinking_msg(interaction, f"Pulling intelligence on **{username}**...")
    await _rlookup(interaction, username)

async def _rlookup(interaction: discord.Interaction, username: str):
    async with aiohttp.ClientSession() as s:
        info = await resolve_username(s, username)
        if not info:
            await edit_original(interaction, embed=err_embed(f"Could not find Roblox user: `{username}`"))
            return
        uid = info["id"]
        R   = await fetch_deep_profile(s, uid)
        R["_av_hash"] = await fetch_avatar_hash(s, R.get("avatar_url",""))

    prof    = R["profile"]
    A       = analyse_profile(R)
    av_info = R.get("avatar_info",{})
    bc      = av_info.get("bodyColors",{})
    av_ass  = av_info.get("assets",[])
    R["_av_fp"] = hashlib.md5(
        (str(sorted(bc.values()))+str(sorted(a.get("id",0) for a in av_ass))).encode()
    ).hexdigest()[:10]

    db_flag = ""
    with db() as con:
        row = con.execute(
            "SELECT reason, flagged_by, flagged_at FROM flags WHERE roblox_id=?", (str(uid),)
        ).fetchone()
    if row:
        ft = datetime.fromtimestamp(row[2], tz=timezone.utc).strftime("%Y-%m-%d")
        db_flag = f"⚑ **FLAGGED** — {row[0]} · by <@{row[1]}> on {ft}"

    groups   = R.get("groups",[])
    badges   = R.get("badges",[])
    games    = R.get("games",[])
    friends  = R.get("friends",[])
    collect  = R.get("collectibles",[])
    prev     = R.get("prev_usernames",[])
    presence = R.get("presence",{})
    scales   = av_info.get("scales",{})
    voice    = R.get("voice_enabled")

    ptype_map = {0:"Offline", 1:"Online — Website", 2:"🟢 In-Game", 3:"🟡 In Studio"}
    pstatus   = ptype_map.get(presence.get("userPresenceType",0),"Offline")
    last_loc  = presence.get("lastLocation","")
    lo_raw    = R.get("last_online","")
    lo_str    = "Unknown"
    if lo_raw:
        try: lo_str = datetime.fromisoformat(lo_raw.replace("Z","+00:00")).strftime("%Y-%m-%d %H:%M UTC")
        except Exception: lo_str = lo_raw[:19]

    pages = []

    # ── PAGE 1 — EXECUTIVE BRIEF ──
    p1 = nexus_embed("NEXUS · Executive Brief", color=SLATE)
    if R.get("avatar_url"):
        p1.set_thumbnail(url=R["avatar_url"])
    p1.add_field(name="🎯 Target",
        value=f"**{prof.get('name','?')}**  (`{uid}`)\nhttps://www.roblox.com/users/{uid}/profile",
        inline=False)
    p1.add_field(name="📊 Scoreboard", value=(
        f"Overall        {score_bar(A['overall'])}\n"
        f"Maturity       {score_bar(A['maturity'])}\n"
        f"Social Graph   {score_bar(A['social'])}\n"
        f"Activity       {score_bar(A['activity'])}\n"
        f"Avatar         {score_bar(A['avatar_custom'])}\n"
        f"Group Presence {score_bar(A['group_footprint'])}"
    ), inline=False)
    p1.add_field(name="🔬 Key Signals", value=(
        f"Age: **{A['age_days']:,}d** · "
        f"Verified: {'✅' if prof.get('hasVerifiedBadge') else '—'} · "
        f"Banned: {'🔴' if prof.get('isBanned') else '—'}\n"
        f"Social size: **{A['social_size']:,}** · "
        f"Groups: **{A['total_groups']}** (high-rank: **{A['high_rank']}**)\n"
        f"Badges: **{A['badge_count']}** · "
        f"Games created: **{A['game_count']}** · "
        f"Avatar assets: **{A['asset_count']}**"
    ), inline=False)
    p1.add_field(name="🧠 Analyst Summary", value=A["analyst"], inline=False)
    if A["flags"]:
        p1.add_field(name="🚩 Automated Flags",
            value="\n".join(f"• ⚠️ {f}" for f in A["flags"]), inline=False)
    if db_flag:
        p1.add_field(name="⚑ Manual Flag", value=db_flag, inline=False)
    pages.append(p1)

    # ── PAGE 2 — IDENTITY & PRESENCE ──
    p2 = nexus_embed("NEXUS · Identity & Presence", color=TEAL)
    if R.get("avatar_url"):
        p2.set_thumbnail(url=R["avatar_url"])
    p2.add_field(name="🧍 Identity", value=(
        f"Username: **{prof.get('name','?')}**\n"
        f"Display:  **{prof.get('displayName','?')}**\n"
        f"Created:  **{A['created_str']}**\n"
        f"Age:      **{A['age_days']:,} days**\n"
        f"Verified: {'✅' if prof.get('hasVerifiedBadge') else '—'}  ·  "
        f"Banned: {'🔴 Yes' if prof.get('isBanned') else '—'}\n"
        f"Voice Chat: {'✅ Enabled' if voice else ('❌ Disabled' if voice is False else '—')}"
    ), inline=False)
    p2.add_field(name="📡 Presence", value=(
        f"**{pstatus}**{f' — {last_loc}' if last_loc else ''}\n"
        f"Last online: **{lo_str}**"
    ), inline=False)
    bio = prof.get("description","").strip()
    p2.add_field(name="📝 Bio", value=bio[:1000] if bio else "*No bio set*", inline=False)
    if prev:
        p2.add_field(name=f"🕰️ Previous Usernames ({len(prev)})",
            value=", ".join(f"`{n}`" for n in prev[:20]), inline=False)
    pages.append(p2)

    # ── PAGE 3 — SOCIAL GRAPH ──
    fc        = R["friends_count"]
    folc      = R["followers_count"]
    fwc       = R["following_count"]
    ff_ratio  = round(folc/fwc, 2) if fwc > 0 else "∞"
    fol_ratio = round(fc/folc, 2)  if folc > 0 else "∞"
    p3 = nexus_embed("NEXUS · Social Graph", color=PURPLE)
    p3.add_field(name="📊 Totals", value=(
        f"Friends:     **{fc:,}**\n"
        f"Followers:   **{R['followers_count']:,}**\n"
        f"Following:   **{R['following_count']:,}**\n"
        f"Social size: **{A['social_size']:,}**"
    ), inline=True)
    p3.add_field(name="📐 Ratios", value=(
        f"Follower/Following: **{ff_ratio}**\n"
        f"Friends/Followers:  **{fol_ratio}**"
    ), inline=True)
    p3.add_field(name="\u200b", value="\u200b", inline=True)
    p3.add_field(name="🧠 Heuristics",
        value="\n".join(f"• {n}" for n in A["social_notes"]), inline=False)
    if friends:
        p3.add_field(
            name=f"👥 Friends Sample ({min(12,len(friends))} of {R['friends_count']})",
            value=", ".join(f"**{f.get('name','?')}**" for f in friends[:12]),
            inline=False)
    pages.append(p3)

    # ── PAGE 4 — GROUPS & AFFILIATIONS ──
    p4 = nexus_embed("NEXUS · Groups & Affiliations", color=GREEN)
    if groups:
        glines = []
        for g in groups[:8]:
            grp  = g.get("group",{}); role = g.get("role",{})
            mc   = grp.get("memberCount",0)
            glines.append(f"**{grp.get('name','?')}** · {role.get('name','?')} (rank {role.get('rank',0)}) · {mc:,} members")
        p4.add_field(name="🏛️ Top Groups", value="\n".join(glines), inline=False)
    else:
        p4.add_field(name="🏛️ Top Groups", value="*No public groups found.*", inline=False)
    p4.add_field(name="📌 Group Footprint", value=(
        f"Total groups: **{A['total_groups']}**\n"
        f"High-rank roles (≥200): **{A['high_rank']}**\n"
        f"Owner-level roles (255): **{A['owner_rank']}**\n"
        f"Avg members (top 10): **{A['avg_members_top']:,}**\n"
        f"Small groups (≤1000): **{A['small_groups']}**"
    ), inline=False)
    pages.append(p4)

    # ── PAGE 5 — AVATAR FORENSICS ──
    p5 = nexus_embed("NEXUS · Avatar Forensics", color=GOLD)
    if R.get("bust_url"):
        p5.set_thumbnail(url=R["bust_url"])
    p5.add_field(name="🧬 Avatar", value=(
        f"Type: **{A['av_type']}**\n"
        f"Assets equipped: **{A['asset_count']}**\n"
        f"Fingerprint: `{A['av_fp']}`\n"
        f"Customization: {score_bar(A['av_score'])}"
    ), inline=False)
    if scales:
        p5.add_field(name="⚖️ Body Scales", value=(
            f"H `{scales.get('height',1.0)}` · W `{scales.get('width',1.0)}` · Head `{scales.get('head',1.0)}`\n"
            f"BodyType `{scales.get('bodyType',0.0)}` · Proportion `{scales.get('proportion',0.0)}`"
        ), inline=False)
    if bc:
        p5.add_field(name="🎨 Body Colors (IDs)", value=(
            f"Head `{bc.get('headColorId','?')}` · Torso `{bc.get('torsoColorId','?')}`\n"
            f"LArm `{bc.get('leftArmColorId','?')}` · RArm `{bc.get('rightArmColorId','?')}`\n"
            f"LLeg `{bc.get('leftLegColorId','?')}` · RLeg `{bc.get('rightLegColorId','?')}`"
        ), inline=False)
    if av_ass:
        asset_lines = [f"• **{a.get('name','?')}** (`{a.get('id','?')}`) — {a.get('assetType',{}).get('name','?')}"
                       for a in av_ass[:10]]
        p5.add_field(name=f"🧥 Equipped Assets (top {min(10,len(av_ass))} of {len(av_ass)})",
            value="\n".join(asset_lines), inline=False)
    pages.append(p5)

    # ── PAGE 6 — ACTIVITY PROFILE ──
    p6 = nexus_embed("NEXUS · Activity Profile", color=BLUE)
    bk = A["badge_buckets"]
    p6.add_field(name="🏅 Badge Behavior", value=(
        f"Last badge: **{A['last_badge']}**\n"
        f"Buckets: 0–7d **{bk['0-7d']}** · 8–30d **{bk['8-30d']}** · 31–90d **{bk['31-90d']}**\n"
        f"91–365d **{bk['91-365d']}** · 366+d **{bk['366+d']}** · unknown **{bk['unknown']}**"
    ), inline=False)
    if badges:
        p6.add_field(name=f"🕐 Recent Badges (sample of {len(badges)})",
            value="\n".join(f"• **{b.get('name','?')}**" for b in badges[:10]), inline=False)
    if games:
        total_v = sum(g.get("placeVisits",0) for g in games)
        total_p = sum(g.get("playing",0) for g in games)
        glines  = [f"• **{g.get('name','?')}** — Visits **{g.get('placeVisits',0):,}**, Playing **{g.get('playing',0)}**"
                   for g in games[:6]]
        p6.add_field(name=f"🎮 Public Games (sample of {len(games)})",
            value=f"Totals: Visits **{total_v:,}**, Playing **{total_p}**\n" + "\n".join(glines),
            inline=False)
    pages.append(p6)

    # ── PAGE 7 — ECONOMY & INVENTORY ──
    p7 = nexus_embed("NEXUS · Economy & Inventory", color=GOLD)
    p7.add_field(name="💰 Limited Items", value=(
        f"Total collectibles: **{A['limited_count']}**\n"
        f"Total RAP: **{A['rap_total']:,}**"
    ), inline=False)
    if collect:
        clines = [f"• **{c.get('name','?')}** — RAP: **{c.get('recentAveragePrice',0):,}** · Serial: `{c.get('serialNumber','?')}`"
                  for c in collect[:10]]
        p7.add_field(name=f"🏷️ Collectibles (top {min(10,len(collect))} of {len(collect)})",
            value="\n".join(clines), inline=False)
    else:
        p7.add_field(name="🏷️ Collectibles", value="*No public limited items found.*", inline=False)
    pages.append(p7)

    store_report(interaction.user.id, {
        "type": "roblox_lookup", "profile": prof, "extra": R,
        "analysis": A, "subject": prof.get("name", username),
    })
    view = PageView(pages)
    await edit_original(interaction, embed=pages[0], view=view)

# ─────────────────────────────────────────────────────
#  /compare_roblox
# ─────────────────────────────────────────────────────
@tree.command(name="compare_roblox", description="Compare two Roblox accounts for alt signals")
@app_commands.describe(user1="First Roblox username", user2="Second Roblox username")
async def compare_roblox(interaction: discord.Interaction, user1: str, user2: str):
    if not get_session(interaction.user.id):
        await interaction.response.send_modal(AuthModal(lambda i, k: _rcompare(i, user1, user2)))
        return
    await thinking_msg(interaction, f"Comparing **{user1}** vs **{user2}**...")
    await _rcompare(interaction, user1, user2)

async def _rcompare(interaction: discord.Interaction, u1: str, u2: str):
    async with aiohttp.ClientSession() as s:
        i1 = await resolve_username(s, u1); i2 = await resolve_username(s, u2)
        if not i1: await send(interaction, embed=err_embed(f"Could not find: `{u1}`")); return
        if not i2: await send(interaction, embed=err_embed(f"Could not find: `{u2}`")); return
        p1 = await fetch_deep_profile(s, i1["id"])
        p2 = await fetch_deep_profile(s, i2["id"])
        p1["_av_hash"] = await fetch_avatar_hash(s, p1.get("avatar_url",""))
        p2["_av_hash"] = await fetch_avatar_hash(s, p2.get("avatar_url",""))

    def make_fp(av):
        bc = av.get("bodyColors",{}); aa = av.get("assets",[])
        return hashlib.md5((str(sorted(bc.values()))+str(sorted(a.get("id",0) for a in aa))).encode()).hexdigest()[:10]
    p1["_av_fp"] = make_fp(p1.get("avatar_info",{}))
    p2["_av_fp"] = make_fp(p2.get("avatar_info",{}))

    A1  = analyse_profile(p1); A2  = analyse_profile(p2)
    res = analyse_alts_roblox(p1, p2)
    score = res["score"]; color = RED if score>=70 else (GOLD if score>=40 else GREEN)
    pr1 = p1["profile"]; pr2 = p2["profile"]

    pages = []
    e1 = nexus_embed("NEXUS · Roblox Alt Comparison", color=color)
    if p1.get("avatar_url"): e1.set_thumbnail(url=p1["avatar_url"])
    e1.add_field(name="⚖️ Subjects", value=(
        f"**A:** {pr1.get('name','?')} (`{i1['id']}`)\n"
        f"**B:** {pr2.get('name','?')} (`{i2['id']}`)"
    ), inline=False)
    e1.add_field(name="🎯 Alt Score",   value=score_bar(score), inline=True)
    e1.add_field(name="📋 Verdict",     value=res["verdict"],   inline=False)
    e1.add_field(name="📊 Overlap", value=(
        f"Shared groups: **{res['shared_groups']}**  ·  "
        f"Mutual friends: **{res['shared_friends']}**  ·  "
        f"Shared badges: **{res['shared_badges']}**"
    ), inline=False)
    pages.append(e1)

    e2 = nexus_embed("NEXUS · Detection Signals", color=color)
    e2.add_field(name="🔎 Signals",
        value="\n".join(res["signals"]) if res["signals"] else "No significant signals.", inline=False)
    pages.append(e2)

    e3 = nexus_embed("NEXUS · Side-by-Side Breakdown", color=SLATE)
    for label, pr, Rx, Ax in [("A", pr1, p1, A1), ("B", pr2, p2, A2)]:
        e3.add_field(name=f"Account {label} — {pr.get('name','?')}", value=(
            f"ID: `{pr.get('id','?')}`\n"
            f"Created: **{Ax['created_str']}** ({Ax['age_days']}d)\n"
            f"Overall: **{Ax['overall']}/100**\n"
            f"Friends: **{Rx.get('friends_count',0):,}** · Groups: **{Ax['total_groups']}**\n"
            f"Badges: **{Ax['badge_count']}** · RAP: **{Ax['rap_total']:,}**\n"
            f"Avatar FP: `{Rx.get('_av_fp','?')}`"
        ), inline=True)
    pages.append(e3)

    store_report(interaction.user.id, {"type":"roblox_compare","user1":p1,"user2":p2,"analysis":res,"a1":A1,"a2":A2})
    await edit_original(interaction, embed=pages[0], view=PageView(pages))

# ─────────────────────────────────────────────────────
#  /compare_discord
# ─────────────────────────────────────────────────────
@tree.command(name="compare_discord", description="Compare two Discord accounts for alt signals")
@app_commands.describe(user1="First user (ID or mention)", user2="Second user (ID or mention)")
async def compare_discord(interaction: discord.Interaction, user1: str, user2: str):
    if not get_session(interaction.user.id):
        await interaction.response.send_modal(AuthModal(lambda i, k: _dcompare(i, user1, user2)))
        return
    await thinking_msg(interaction, "Comparing Discord accounts...")
    await _dcompare(interaction, user1, user2)

async def _dcompare(interaction: discord.Interaction, u1s: str, u2s: str):
    def parse_id(s):
        try: return int(s.strip().strip("<@!>"))
        except ValueError: return None
    id1 = parse_id(u1s); id2 = parse_id(u2s)
    if not id1 or not id2:
        await edit_original(interaction, embed=err_embed("Provide valid user IDs or mentions.")); return
    try:
        m1 = await bot.fetch_user(id1); m2 = await bot.fetch_user(id2)
    except discord.NotFound as e:
        await edit_original(interaction, embed=err_embed(f"User not found: {e}")); return

    mutual = [g for g in bot.guilds if g.get_member(id1) and g.get_member(id2)]
    res    = analyse_alts_discord(m1, m2, mutual)
    score  = res["score"]; color = RED if score>=70 else (GOLD if score>=40 else GREEN)
    now    = datetime.now(timezone.utc)

    def user_block(u):
        age = (now - u.created_at).days
        return f"**{u.name}** (`{u.id}`)\nCreated: **{u.created_at.strftime('%B %d, %Y')}** ({age}d)\nBot: {'Yes' if u.bot else 'No'}"

    pages = []
    e1 = nexus_embed("NEXUS · Discord Alt Comparison", color=color)
    if m1.avatar: e1.set_thumbnail(url=m1.avatar.url)
    e1.add_field(name="Account A", value=user_block(m1), inline=True)
    e1.add_field(name="Account B", value=user_block(m2), inline=True)
    e1.add_field(name="\u200b", value="\u200b", inline=True)
    e1.add_field(name="🎯 Alt Score", value=score_bar(score), inline=True)
    e1.add_field(name="📋 Verdict",   value=res["verdict"],  inline=False)
    pages.append(e1)

    e2 = nexus_embed("NEXUS · Discord Signals", color=color)
    e2.add_field(name="🔎 Detection Signals",
        value="\n".join(res["signals"]) if res["signals"] else "No significant signals.", inline=False)
    if mutual:
        e2.add_field(name=f"🏠 Mutual Servers ({len(mutual)})",
            value="\n".join(f"• **{g.name}**" for g in mutual[:10]), inline=False)
    pages.append(e2)

    store_report(interaction.user.id, {
        "type":"discord_compare",
        "user1":{"name":m1.name,"id":str(m1.id),"created":m1.created_at.strftime("%Y-%m-%d")},
        "user2":{"name":m2.name,"id":str(m2.id),"created":m2.created_at.strftime("%Y-%m-%d")},
        "analysis":res,
    })
    await edit_original(interaction, embed=pages[0], view=PageView(pages))

# ─────────────────────────────────────────────────────
#  /flag  /flags  /unflag
# ─────────────────────────────────────────────────────
@tree.command(name="flag", description="Flag a Roblox user as a person of interest")
@app_commands.describe(username="Roblox username", reason="Reason for flagging")
async def flag_cmd(interaction: discord.Interaction, username: str, reason: str):
    if not get_session(interaction.user.id):
        await interaction.response.send_modal(AuthModal(lambda i, k: _flag(i, username, reason))); return
    await thinking_msg(interaction, f"Flagging **{username}**...")
    await _flag(interaction, username, reason)

async def _flag(interaction: discord.Interaction, username: str, reason: str):
    async with aiohttp.ClientSession() as s:
        info = await resolve_username(s, username)
    if not info:
        await edit_original(interaction, embed=err_embed(f"Could not find: `{username}`")); return
    with db() as con:
        con.execute("INSERT OR REPLACE INTO flags VALUES (?,?,?,?,?)",
                    (str(info["id"]), info["username"], reason, str(interaction.user.id), int(time.time())))
    e = nexus_embed("⚑ User Flagged", color=RED)
    e.add_field(name="Username",  value=info["username"],  inline=True)
    e.add_field(name="Roblox ID", value=str(info["id"]),   inline=True)
    e.add_field(name="Reason",    value=reason,             inline=False)
    await edit_original(interaction, embed=e)

@tree.command(name="flags", description="List all flagged Roblox users")
async def flags_cmd(interaction: discord.Interaction):
    if not get_session(interaction.user.id):
        await interaction.response.send_modal(AuthModal(lambda i, k: _flags(i))); return
    await thinking_msg(interaction, "Loading flagged users...")
    await _flags(interaction)

async def _flags(interaction: discord.Interaction):
    with db() as con:
        rows = con.execute(
            "SELECT username, roblox_id, reason, flagged_by, flagged_at FROM flags ORDER BY flagged_at DESC"
        ).fetchall()
    if not rows:
        await edit_original(interaction, embed=nexus_embed("⚑ Flagged Users","No flagged users.",RED)); return
    pages = []
    for i in range(0, len(rows), 6):
        chunk = rows[i:i+6]
        e = nexus_embed(f"⚑ Flagged Users — {len(rows)} total", color=RED)
        for uname, rid, rsn, by, at in chunk:
            at_str = datetime.fromtimestamp(at, tz=timezone.utc).strftime("%Y-%m-%d")
            e.add_field(name=f"{uname}  (`{rid}`)",
                value=f"**{rsn}**\nFlagged by <@{by}> · {at_str}", inline=False)
        pages.append(e)
    await edit_original(interaction, embed=pages[0], view=PageView(pages))

@tree.command(name="unflag", description="Remove a flag from a Roblox user")
@app_commands.describe(username="Roblox username to unflag")
async def unflag_cmd(interaction: discord.Interaction, username: str):
    if not get_session(interaction.user.id):
        await interaction.response.send_modal(AuthModal(lambda i, k: _unflag(i, username))); return
    await thinking_msg(interaction, f"Unflagging **{username}**...")
    await _unflag(interaction, username)

async def _unflag(interaction: discord.Interaction, username: str):
    with db() as con:
        row = con.execute("SELECT roblox_id FROM flags WHERE username=?", (username,)).fetchone()
        if row:
            con.execute("DELETE FROM flags WHERE roblox_id=?", (row[0],))
            await edit_original(interaction, embed=nexus_embed("✅ Unflagged", f"`{username}` removed.", GREEN))
        else:
            await edit_original(interaction, embed=err_embed(f"`{username}` is not flagged."))

# ─────────────────────────────────────────────────────
#  /key_manage
# ─────────────────────────────────────────────────────
class AddKeyModal(ui.Modal, title="Add Access Key"):
    lbl = ui.TextInput(label="Key Label", placeholder="e.g. Moderator Team", max_length=64)
    val = ui.TextInput(label="Key Value", placeholder="The actual key string", max_length=128)

    async def on_submit(self, interaction: discord.Interaction):
        label = self.lbl.value.strip(); value = self.val.value.strip()
        if value == OWNER_KEY:
            await interaction.response.send_message(embed=err_embed("Cannot add the owner key."), ephemeral=True); return
        with db() as con:
            try:
                con.execute("INSERT INTO auth_keys (label,value,created) VALUES (?,?,?)",
                            (label, value, int(time.time())))
                await interaction.response.send_message(
                    embed=nexus_embed("✅ Key Added", f"**{label}** added successfully.", GREEN), ephemeral=True)
            except sqlite3.IntegrityError:
                await interaction.response.send_message(embed=err_embed("Key value already exists."), ephemeral=True)

class DeleteKeyModal(ui.Modal, title="Delete Access Key"):
    kid = ui.TextInput(label="Key ID (from list)", placeholder="e.g. 3", max_length=6)

    async def on_submit(self, interaction: discord.Interaction):
        try: n = int(self.kid.value.strip())
        except ValueError:
            await interaction.response.send_message(embed=err_embed("Invalid ID."), ephemeral=True); return
        with db() as con:
            row = con.execute("SELECT label FROM auth_keys WHERE id=?", (n,)).fetchone()
            if row:
                con.execute("DELETE FROM auth_keys WHERE id=?", (n,))
                await interaction.response.send_message(
                    embed=nexus_embed("✅ Deleted", f"Key **{row[0]}** removed.", GREEN), ephemeral=True)
            else:
                await interaction.response.send_message(embed=err_embed(f"No key with ID `{n}`."), ephemeral=True)

class KeyManageView(ui.View):
    def __init__(self): super().__init__(timeout=120)

    @ui.button(label="➕ Add Key", style=discord.ButtonStyle.success)
    async def add(self, interaction: discord.Interaction, _: ui.Button):
        await interaction.response.send_modal(AddKeyModal())

    @ui.button(label="🗑️ Delete Key", style=discord.ButtonStyle.danger)
    async def delete(self, interaction: discord.Interaction, _: ui.Button):
        await interaction.response.send_modal(DeleteKeyModal())

@tree.command(name="key_manage", description="Manage Nexus access keys (owner key required)")
async def key_manage(interaction: discord.Interaction):
    async def after(intr: discord.Interaction, key: str):
        if not is_owner_key(key):
            await intr.response.send_message(
                embed=err_embed("Key management requires the **owner key**."), ephemeral=True); return
        with db() as con:
            rows = con.execute("SELECT id, label, value, created FROM auth_keys ORDER BY created DESC").fetchall()
        e = nexus_embed("🔑 Key Management", color=GOLD)
        if rows:
            for kid, label, value, created in rows:
                at = datetime.fromtimestamp(created, tz=timezone.utc).strftime("%Y-%m-%d")
                e.add_field(name=f"[{kid}] {label}",
                    value=f"`{value[:4]}{'•'*max(0,len(value)-4)}` · Added {at}", inline=False)
        else:
            e.description = "No keys configured yet."
        view = KeyManageView()
        if intr.response.is_done(): await intr.followup.send(embed=e, view=view, ephemeral=True)
        else: await intr.response.send_message(embed=e, view=view, ephemeral=True)
    await interaction.response.send_modal(AuthModal(after))

# ─────────────────────────────────────────────────────
#  /logout
# ─────────────────────────────────────────────────────
@tree.command(name="logout", description="End your current Nexus session")
async def logout_cmd(interaction: discord.Interaction):
    destroy_session(interaction.user.id)
    await interaction.response.send_message(embed=nexus_embed("🔒 Session Ended",
        "Logged out. Re-authenticate with your access key to continue.", SLATE))

# ─────────────────────────────────────────────────────
#  /export
# ─────────────────────────────────────────────────────
@tree.command(name="export", description="Export your last report as a formatted intelligence PDF")
async def export_cmd(interaction: discord.Interaction):
    if not get_session(interaction.user.id):
        await interaction.response.send_modal(AuthModal(lambda i, k: _export(i))); return
    await thinking_msg(interaction, "Generating intelligence PDF...")
    await _export(interaction)

async def _export(interaction: discord.Interaction):
    report = get_report(interaction.user.id)
    if not report:
        await edit_original(interaction, embed=err_embed("No report to export. Run a lookup or compare command first.")); return
    try:
        loop = asyncio.get_event_loop()
        pdf  = await asyncio.wait_for(
            loop.run_in_executor(None, build_pdf, report),
            timeout=30
        )
    except asyncio.TimeoutError:
        await edit_original(interaction, embed=err_embed("PDF generation timed out. Try again.")); return
    except Exception as ex:
        await edit_original(interaction, embed=err_embed(f"PDF generation failed: {ex}")); return

    subject  = report.get("subject", "report")
    filename = f"nexus_{report.get('type','report')}_{subject[:20].replace(' ','_')}.pdf"
    e = nexus_embed("📄 Intelligence Report", color=BLUE)
    e.add_field(name="Type",      value=f"`{report.get('type','?')}`",  inline=True)
    e.add_field(name="Subject",   value=f"`{subject}`",                  inline=True)
    e.add_field(name="Generated", value=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), inline=True)

    # Edit the thinking message to show completion, then send file as followup
    # (attachments on edit_original_response is unreliable for user-installed apps)
    await edit_original(interaction, embed=e)
    await interaction.followup.send(file=discord.File(io.BytesIO(pdf), filename=filename))

# ─────────────────────────────────────────────────────
#  PDF BUILDER
# ─────────────────────────────────────────────────────
C_BG     = colors.HexColor("#0f1117")
C_PANEL  = colors.HexColor("#1a1d27")
C_ACCENT = colors.HexColor("#3b82f6")
C_GOLD   = colors.HexColor("#f59e0b")
C_RED    = colors.HexColor("#ef4444")
C_GREEN  = colors.HexColor("#22c55e")
C_TEXT   = colors.HexColor("#e2e8f0")
C_MUTED  = colors.HexColor("#64748b")
C_BORDER = colors.HexColor("#2d3748")

def _ps(name, **kw):
    d = dict(fontName="Helvetica", fontSize=9, textColor=C_TEXT, leading=14)
    d.update(kw); return ParagraphStyle(name, **d)

PDF_S = {
    "title":  _ps("T",  fontSize=22, textColor=C_ACCENT, fontName="Helvetica-Bold", alignment=TA_CENTER, spaceAfter=2),
    "cls":    _ps("CL", fontSize=9,  textColor=C_RED,    fontName="Helvetica-Bold", alignment=TA_CENTER, spaceAfter=1),
    "meta":   _ps("M",  fontSize=8,  textColor=C_MUTED,  alignment=TA_CENTER, spaceAfter=1),
    "h1":     _ps("H1", fontSize=14, textColor=C_ACCENT, fontName="Helvetica-Bold", spaceBefore=14, spaceAfter=5, borderPad=4),
    "h2":     _ps("H2", fontSize=10, textColor=C_GOLD,   fontName="Helvetica-Bold", spaceBefore=8, spaceAfter=3),
    "body":   _ps("B"),
    "mono":   _ps("Mo", fontName="Courier", fontSize=8, textColor=C_TEXT, backColor=C_PANEL, leftIndent=8, rightIndent=8, leading=12, spaceAfter=4),
    "verdict":_ps("V",  fontSize=12, textColor=colors.white, fontName="Helvetica-Bold", alignment=TA_CENTER),
    "flag":   _ps("F",  fontSize=9,  textColor=C_RED, leading=14),
    "small":  _ps("S",  fontSize=7,  textColor=C_MUTED, alignment=TA_RIGHT),
    "score_l":_ps("SL", fontSize=8,  textColor=C_TEXT, leading=12),
    "score_v":_ps("SV", fontSize=8,  textColor=C_TEXT, fontName="Helvetica-Bold", leading=12),
}

def _kv(story, pairs):
    data = [[Paragraph(f"<b>{k}</b>", PDF_S["body"]), Paragraph(str(v), PDF_S["body"])] for k, v in pairs]
    t = Table(data, colWidths=[1.9*inch, 5.1*inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0),(0,-1), C_PANEL),
        ("BACKGROUND", (1,0),(1,-1), C_BG),
        ("TEXTCOLOR",  (0,0),(-1,-1), C_TEXT),
        ("FONTNAME",   (0,0),(0,-1), "Helvetica-Bold"),
        ("ROWPADDING", (0,0),(-1,-1), 5),
        ("GRID",       (0,0),(-1,-1), 0.4, C_BORDER),
        ("VALIGN",     (0,0),(-1,-1), "TOP"),
    ]))
    story.append(t); story.append(Spacer(1,5))

def _tbl(story, rows, widths=None):
    if not rows or len(rows) < 2: return
    n  = len(rows[0])
    cw = widths or [7.0*inch/n]*n
    t  = Table(rows, colWidths=cw)
    t.setStyle(TableStyle([
        ("BACKGROUND",     (0,0),(-1,0),  C_ACCENT),
        ("TEXTCOLOR",      (0,0),(-1,0),  colors.black),
        ("FONTNAME",       (0,0),(-1,0),  "Helvetica-Bold"),
        ("FONTSIZE",       (0,0),(-1,-1), 7.5),
        ("BACKGROUND",     (0,1),(-1,-1), C_BG),
        ("ROWBACKGROUNDS", (0,1),(-1,-1), [C_BG, C_PANEL]),
        ("TEXTCOLOR",      (0,1),(-1,-1), C_TEXT),
        ("ROWPADDING",     (0,0),(-1,-1), 4),
        ("GRID",           (0,0),(-1,-1), 0.3, C_BORDER),
    ]))
    story.append(t); story.append(Spacer(1,5))

def _score_bar_pdf(story, label: str, score: int):
    filled = round(score/100*22); empty = 22-filled
    sc = C_GREEN if score>=70 else (C_GOLD if score>=40 else C_RED)
    bar_style = ParagraphStyle("PB", fontName="Courier", fontSize=8, textColor=sc, leading=12)
    num_style  = ParagraphStyle("PN", fontName="Helvetica-Bold", fontSize=8, textColor=C_TEXT, leading=12, alignment=TA_RIGHT)
    t = Table([[
        Paragraph(label, PDF_S["score_l"]),
        Paragraph("█"*filled + "░"*empty, bar_style),
        Paragraph(f"{score}/100", num_style),
    ]], colWidths=[1.5*inch, 3.8*inch, 0.7*inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0),(-1,-1), C_PANEL),
        ("ROWPADDING", (0,0),(-1,-1), 4),
        ("GRID",       (0,0),(-1,-1), 0.3, C_BORDER),
    ]))
    story.append(t); story.append(Spacer(1,2))

def build_pdf(report: dict) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter,
                             leftMargin=0.65*inch, rightMargin=0.65*inch,
                             topMargin=0.65*inch,  bottomMargin=0.65*inch)
    story = []
    now_s = datetime.now(timezone.utc).strftime("%Y-%m-%d  %H:%M:%S UTC")

    # ── HEADER ──
    story += [
        Spacer(1, 0.05*inch),
        Paragraph("NEXUS INTELLIGENCE REPORT", PDF_S["title"]),
        Paragraph("RESTRICTED — AUTHORIZED USE ONLY", PDF_S["cls"]),
        Paragraph(f"Report generated  {now_s}", PDF_S["meta"]),
        Spacer(1, 5),
        HRFlowable(width="100%", thickness=2, color=C_ACCENT, spaceAfter=10),
    ]

    rtype = report.get("type","")

    # ── ROBLOX LOOKUP ──
    if rtype == "roblox_lookup":
        prof = report.get("profile",{}); R = report.get("extra",{}); A = report.get("analysis",{})
        story.append(Paragraph("SUBJECT INTELLIGENCE — ROBLOX", PDF_S["h1"]))

        story.append(Paragraph("ASSESSMENT SCORES", PDF_S["h2"]))
        for lbl, key in [("Overall","overall"),("Account Maturity","maturity"),
                          ("Social Graph","social"),("Activity","activity"),
                          ("Avatar Customization","avatar_custom"),("Group Presence","group_footprint")]:
            _score_bar_pdf(story, lbl, A.get(key,0))
        story.append(Spacer(1,6))

        story.append(Paragraph("CORE IDENTITY", PDF_S["h2"]))
        _kv(story,[
            ("Username",        prof.get("name","N/A")),
            ("Display Name",    prof.get("displayName","N/A")),
            ("User ID",         str(prof.get("id","N/A"))),
            ("Account Created", A.get("created_str","N/A")),
            ("Account Age",     f"{A.get('age_days',0):,} days"),
            ("Verified Badge",  "Yes" if prof.get("hasVerifiedBadge") else "No"),
            ("Banned",          "YES" if prof.get("isBanned") else "No"),
            ("Voice Chat",      "Enabled" if R.get("voice_enabled") else ("Disabled" if R.get("voice_enabled") is False else "Unknown")),
            ("Last Online",     (R.get("last_online","")[:19] or "Unknown")),
        ])

        if prof.get("description"):
            story.append(Paragraph("BIO / DESCRIPTION", PDF_S["h2"]))
            story.append(Paragraph(prof["description"].replace("\n","<br/>"), PDF_S["mono"]))

        prev = R.get("prev_usernames",[])
        if prev:
            story.append(Paragraph("PREVIOUS USERNAMES", PDF_S["h2"]))
            story.append(Paragraph(", ".join(prev), PDF_S["body"]))
            story.append(Spacer(1,4))

        story.append(Paragraph("SOCIAL GRAPH", PDF_S["h2"]))
        fc = R.get("friends_count",0); folc = R.get("followers_count",0); fwc = R.get("following_count",0)
        _kv(story,[
            ("Friends",        f"{fc:,}"),
            ("Followers",      f"{folc:,}"),
            ("Following",      f"{fwc:,}"),
            ("Social Size",    f"{fc+folc+fwc:,}"),
            ("Flwr/Fwing Ratio", str(round(folc/fwc,2)) if fwc>0 else "∞"),
            ("Analysis Notes", " · ".join(A.get("social_notes",["N/A"]))),
        ])

        groups = R.get("groups",[])
        if groups:
            story.append(Paragraph(f"GROUP MEMBERSHIPS  ({len(groups)} total)", PDF_S["h2"]))
            gdata = [["Group Name","Role","Rank","Members"]]
            for g in groups[:25]:
                grp  = g.get("group",{}); role = g.get("role",{})
                gdata.append([grp.get("name","?")[:38], role.get("name","?")[:22],
                               str(role.get("rank","?")), f"{grp.get('memberCount',0):,}"])
            _tbl(story, gdata, [3.1*inch,1.8*inch,0.7*inch,1.4*inch])

        story.append(Paragraph("AVATAR FORENSICS", PDF_S["h2"]))
        av_info = R.get("avatar_info",{}); bc = av_info.get("bodyColors",{}); sc = av_info.get("scales",{})
        _kv(story,[
            ("Avatar Type",        A.get("av_type","R6")),
            ("Assets Equipped",    str(A.get("asset_count",0))),
            ("Fingerprint",        A.get("av_fp","N/A")),
            ("Customization Score",f"{A.get('av_score',0)}/100"),
            ("Scale H / W / Head", f"{sc.get('height',1.0)} / {sc.get('width',1.0)} / {sc.get('head',1.0)}"),
            ("BodyType / Prop",    f"{sc.get('bodyType',0.0)} / {sc.get('proportion',0.0)}"),
            ("Head / Torso Color", f"{bc.get('headColorId','?')} / {bc.get('torsoColorId','?')}"),
            ("Arm Color IDs",      f"L:{bc.get('leftArmColorId','?')}  R:{bc.get('rightArmColorId','?')}"),
            ("Leg Color IDs",      f"L:{bc.get('leftLegColorId','?')}  R:{bc.get('rightLegColorId','?')}"),
        ])

        story.append(Paragraph("ECONOMY & INVENTORY", PDF_S["h2"]))
        _kv(story,[
            ("Collectibles", str(A.get("limited_count",0))),
            ("Total RAP",    f"{A.get('rap_total',0):,}"),
        ])
        collect = R.get("collectibles",[])
        if collect:
            cd = [["Item Name","RAP","Serial #"]]
            for c in collect[:15]:
                cd.append([c.get("name","?")[:40], f"{c.get('recentAveragePrice',0):,}", str(c.get("serialNumber","?"))])
            _tbl(story, cd, [4.2*inch,1.4*inch,1.4*inch])

        story.append(Paragraph("ACTIVITY PROFILE", PDF_S["h2"]))
        bk = A.get("badge_buckets",{})
        _kv(story,[
            ("Last Badge",   A.get("last_badge","None")),
            ("0–7 days",     str(bk.get("0-7d",0))),
            ("8–30 days",    str(bk.get("8-30d",0))),
            ("31–90 days",   str(bk.get("31-90d",0))),
            ("91–365 days",  str(bk.get("91-365d",0))),
            ("366+ days",    str(bk.get("366+d",0))),
            ("Unknown date", str(bk.get("unknown",0))),
        ])

        story.append(Paragraph("ANALYST SUMMARY", PDF_S["h2"]))
        story.append(Paragraph(A.get("analyst","N/A"), PDF_S["body"]))
        story.append(Spacer(1,4))

        flags = A.get("flags",[])
        if flags:
            story.append(Paragraph("AUTOMATED FLAGS", PDF_S["h2"]))
            for f in flags:
                story.append(Paragraph(f"  ⚠ {f}", PDF_S["flag"]))

    # ── ROBLOX COMPARE ──
    elif rtype == "roblox_compare":
        story.append(Paragraph("ALT ACCOUNT ANALYSIS — ROBLOX", PDF_S["h1"]))
        u1 = report["user1"]; u2 = report["user2"]
        res = report["analysis"]; A1 = report.get("a1",{}); A2 = report.get("a2",{})
        pr1 = u1.get("profile",{}); pr2 = u2.get("profile",{})
        score = res["score"]

        story.append(Paragraph("SUBJECTS", PDF_S["h2"]))
        _kv(story,[("Account A", f"{pr1.get('name','?')}  (ID: {pr1.get('id','?')})"),
                   ("Account B", f"{pr2.get('name','?')}  (ID: {pr2.get('id','?')})")])

        story.append(Spacer(1,6))
        sc_col = C_RED if score>=70 else (C_GOLD if score>=40 else C_GREEN)
        st = Table([[Paragraph(f"ALT LIKELIHOOD: {score}/100", PDF_S["verdict"]),
                     Paragraph(res["verdict"], PDF_S["verdict"])]],
                   colWidths=[2.4*inch,4.6*inch])
        st.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(0,0),sc_col),("BACKGROUND",(1,0),(1,0),C_PANEL),
            ("BOX",(0,0),(-1,-1),1,C_ACCENT),("ROWPADDING",(0,0),(-1,-1),8),("VALIGN",(0,0),(-1,-1),"MIDDLE"),
        ]))
        story += [st, Spacer(1,10)]

        story.append(Paragraph("DETECTION SIGNALS", PDF_S["h2"]))
        for sig in res.get("signals",[]) or ["No signals detected."]:
            story.append(Paragraph(f"  {sig}", PDF_S["body"]))

        story.append(Paragraph("OVERLAP STATISTICS", PDF_S["h2"]))
        _kv(story,[("Shared Groups",str(res.get("shared_groups",0))),
                   ("Mutual Friends",str(res.get("shared_friends",0))),
                   ("Shared Badges",str(res.get("shared_badges",0)))])

        story.append(Paragraph("SIDE-BY-SIDE COMPARISON", PDF_S["h2"]))
        _kv(story,[
            ("A — Username",      pr1.get("name","?")),
            ("A — Created",       A1.get("created_str","?")),
            ("A — Overall Score", f"{A1.get('overall',0)}/100"),
            ("A — RAP",           f"{A1.get('rap_total',0):,}"),
            ("A — Avatar FP",     u1.get("_av_fp","?")),
            ("B — Username",      pr2.get("name","?")),
            ("B — Created",       A2.get("created_str","?")),
            ("B — Overall Score", f"{A2.get('overall',0)}/100"),
            ("B — RAP",           f"{A2.get('rap_total',0):,}"),
            ("B — Avatar FP",     u2.get("_av_fp","?")),
        ])

    # ── DISCORD COMPARE ──
    elif rtype == "discord_compare":
        story.append(Paragraph("ALT ACCOUNT ANALYSIS — DISCORD", PDF_S["h1"]))
        u1 = report["user1"]; u2 = report["user2"]; res = report["analysis"]
        score = res["score"]

        story.append(Paragraph("SUBJECTS", PDF_S["h2"]))
        _kv(story,[
            ("Account A", f"{u1['name']}  (ID: {u1['id']})  —  created {u1['created']}"),
            ("Account B", f"{u2['name']}  (ID: {u2['id']})  —  created {u2['created']}"),
        ])
        story.append(Spacer(1,6))
        sc_col = C_RED if score>=70 else (C_GOLD if score>=40 else C_GREEN)
        st = Table([[Paragraph(f"ALT LIKELIHOOD: {score}/100", PDF_S["verdict"]),
                     Paragraph(res["verdict"], PDF_S["verdict"])]],
                   colWidths=[2.4*inch,4.6*inch])
        st.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(0,0),sc_col),("BACKGROUND",(1,0),(1,0),C_PANEL),
            ("BOX",(0,0),(-1,-1),1,C_ACCENT),("ROWPADDING",(0,0),(-1,-1),8),("VALIGN",(0,0),(-1,-1),"MIDDLE"),
        ]))
        story += [st, Spacer(1,10)]

        story.append(Paragraph("DETECTION SIGNALS", PDF_S["h2"]))
        for sig in res.get("signals",[]) or ["No signals detected."]:
            story.append(Paragraph(f"  {sig}", PDF_S["body"]))


    # ── GROUP LOOKUP ──
    elif rtype == "group_lookup":
        info = report.get("info", {})
        G    = report.get("extra", {})
        A    = report.get("analysis", {})

        story.append(Paragraph("GROUP INTELLIGENCE — ROBLOX", PDF_S["h1"]))

        story.append(Paragraph("ASSESSMENT SCORES", PDF_S["h2"]))
        for lbl, key in [("Overall","overall"),("Maturity","maturity"),
                          ("Size","size"),("Activity","activity")]:
            _score_bar_pdf(story, lbl, A.get(key, 0))
        story.append(Spacer(1, 6))

        story.append(Paragraph("CORE IDENTITY", PDF_S["h2"]))
        owner = info.get("owner", {})
        _kv(story, [
            ("Group Name",    info.get("name", "N/A")),
            ("Group ID",      str(info.get("id", "N/A"))),
            ("Created",       A.get("created_str", "N/A")),
            ("Age",           f"{A.get('age_days', 0):,} days"),
            ("Members",       f"{A.get('member_count', 0):,}"),
            ("Public Entry",  "Yes" if info.get("publicEntryAllowed") else "No"),
            ("Locked",        "Yes" if info.get("isLocked") else "No"),
            ("Verified",      "Yes" if info.get("hasVerifiedBadge") else "No"),
            ("Owner",         f"{owner.get('username','?')} (ID: {owner.get('userId','?')})"),
        ])

        desc = info.get("description", "").strip()
        if desc:
            story.append(Paragraph("DESCRIPTION", PDF_S["h2"]))
            story.append(Paragraph(desc.replace("\n", "<br/>"), PDF_S["mono"]))
            story.append(Spacer(1, 4))

        shout = G.get("shout")
        if shout and shout.get("body"):
            story.append(Paragraph("GROUP SHOUT", PDF_S["h2"]))
            shout_poster = shout.get("poster", {})
            shout_ts = (shout.get("updated", "") or shout.get("created", ""))[:10]
            story.append(Paragraph(
                f"{shout.get('body','')[:400]}  —  {shout_poster.get('username','?')} ({shout_ts})",
                PDF_S["body"]))
            story.append(Spacer(1, 4))

        story.append(Paragraph("SOCIAL METRICS", PDF_S["h2"]))
        _kv(story, [
            ("Total Roles",           str(A.get("total_roles", 0))),
            ("High-Authority Roles",  str(len(A.get("high_roles", [])))),
            ("Owner Role Name",       A.get("top_role_name", "?")),
            ("Allies",                str(A.get("ally_count", 0))),
            ("Enemies",               str(A.get("enemy_count", 0))),
            ("Public Games",          str(A.get("game_count", 0))),
            ("Last Wall Post",        A.get("last_post", "Unknown")),
        ])

        roles = G.get("roles", [])
        if roles:
            story.append(Paragraph(f"ROLE STRUCTURE  ({len(roles)} total)", PDF_S["h2"]))
            rdata = [["Rank", "Role Name", "Members"]]
            for r in sorted(roles, key=lambda x: x.get("rank", 0), reverse=True)[:25]:
                rdata.append([
                    str(r.get("rank", "?")),
                    r.get("name", "?")[:40],
                    f"{r.get('memberCount', 0):,}",
                ])
            _tbl(story, rdata, [0.8*inch, 4.4*inch, 1.8*inch])

        wall = G.get("wall", [])
        if wall:
            story.append(Paragraph(f"RECENT WALL POSTS  ({len(wall)} loaded)", PDF_S["h2"]))
            wdata = [["User", "Date", "Post"]]
            for post in wall[:8]:
                poster = post.get("poster") or {}
                body   = (post.get("body", "") or "")[:80].replace("\n", " ")
                ts     = (post.get("updated", "") or post.get("created", ""))[:10]
                wdata.append([poster.get("username", "?")[:20], ts, body])
            _tbl(story, wdata, [1.4*inch, 1.0*inch, 4.6*inch])

        # Use full paginated lists for PDF (embed uses the capped preview)
        allies  = G.get("allies_full", G.get("allies", []))
        enemies = G.get("enemies_full", G.get("enemies", []))
        if allies or enemies:
            story.append(Paragraph(
                f"AFFILIATIONS  ({len(allies)} allies, {len(enemies)} enemies)",
                PDF_S["h2"]))
            affil = []
            for a in allies:
                affil.append(("Allied", a.get("name","?"), f"{a.get('memberCount',0):,}"))
            for e in enemies:
                affil.append(("Enemy", e.get("name","?"), f"{e.get('memberCount',0):,}"))
            adata = [["Type", "Group Name", "Members"]] + affil
            _tbl(story, adata, [0.8*inch, 4.4*inch, 1.8*inch])

        games = G.get("games", [])
        if games:
            story.append(Paragraph(f"PUBLIC GAMES  ({len(games)})", PDF_S["h2"]))
            gdata = [["Game Name", "Visits", "Playing"]]
            for g in games[:10]:
                gdata.append([
                    g.get("name", "?")[:45],
                    f"{g.get('placeVisits', 0):,}",
                    str(g.get("playing", 0)),
                ])
            _tbl(story, gdata, [4.5*inch, 1.5*inch, 1.0*inch])

        if A.get("flags"):
            story.append(Paragraph("AUTOMATED FLAGS", PDF_S["h2"]))
            for f in A["flags"]:
                story.append(Paragraph(f"  ⚠ {f}", PDF_S["flag"]))
        if A.get("notes"):
            story.append(Paragraph("ANALYST NOTES", PDF_S["h2"]))
            for n in A["notes"]:
                story.append(Paragraph(f"  • {n}", PDF_S["body"]))

    # ── GAME LOOKUP ──
    elif rtype == "game_lookup":
        details = report.get("details", {})
        G       = report.get("extra", {})
        A       = report.get("analysis", {})

        story.append(Paragraph("GAME INTELLIGENCE — ROBLOX", PDF_S["h1"]))

        story.append(Paragraph("ASSESSMENT SCORES", PDF_S["h2"]))
        for lbl, key in [("Overall","overall"),("Popularity","popularity"),
                          ("Reception","quality"),("Engagement","engagement")]:
            _score_bar_pdf(story, lbl, A.get(key, 0))
        story.append(Spacer(1, 6))

        creator = details.get("creator", {})
        ctype   = creator.get("type", "?")
        cid     = creator.get("id", "?")
        curl    = (f"roblox.com/groups/{cid}" if ctype == "Group"
                   else f"roblox.com/users/{cid}/profile")

        story.append(Paragraph("CORE IDENTITY", PDF_S["h2"]))
        _kv(story, [
            ("Game Name",     details.get("name", "N/A")),
            ("Universe ID",   str(details.get("id", "N/A"))),
            ("Root Place ID", str(details.get("rootPlaceId", "N/A"))),
            ("Genre",         details.get("genre", "N/A")),
            ("Max Players",   str(A.get("max_players", 0))),
            ("Created",       A.get("created_str", "N/A")),
            ("Last Updated",  A.get("updated_str", "N/A")),
            ("Age",           f"{A.get('age_days', 0):,} days"),
            ("Copylocked",    "Yes" if details.get("isCopylocked") else "No"),
            ("Creator",       f"{creator.get('name','?')} ({ctype}) — {curl}"),
        ])

        desc = details.get("description", "").strip()
        if desc:
            story.append(Paragraph("DESCRIPTION", PDF_S["h2"]))
            story.append(Paragraph(desc.replace("\n", "<br/>"), PDF_S["mono"]))
            story.append(Spacer(1, 4))

        story.append(Paragraph("PERFORMANCE METRICS", PDF_S["h2"]))
        _kv(story, [
            ("Total Visits",        f"{A.get('visits', 0):,}"),
            ("Concurrent Players",  f"{A.get('playing', 0):,}"),
            ("Favorited",           f"{A.get('favs', 0):,}"),
            ("Visit / Fav Ratio",   f"{round(A.get('visits',0)/max(A.get('favs',1),1),1)}:1"),
            ("Upvotes",             f"{A.get('up_votes', 0):,}"),
            ("Downvotes",           f"{A.get('dn_votes', 0):,}"),
            ("Approval Rating",     f"{A.get('like_pct', 0)}%"),
            ("Total Votes",         f"{A.get('total_votes', 0):,}"),
        ])

        servers = G.get("servers", [])
        if servers:
            story.append(Paragraph(f"SERVER SNAPSHOT  ({A.get('active_servers',0)} active)", PDF_S["h2"]))
            _kv(story, [
                ("Active Servers",      str(A.get("active_servers", 0))),
                ("Players in Servers",  str(A.get("total_players", 0))),
                ("Avg Server Fill",     f"{A.get('avg_server_fill', 0)}%"),
                ("Max Per Server",      str(A.get("max_players", 0))),
            ])
            svdata = [["Players", "Capacity", "Ping (ms)", "FPS"]]
            for sv in servers[:8]:
                svdata.append([
                    str(sv.get("playing", 0)),
                    str(sv.get("maxPlayers", A.get("max_players", 0))),
                    str(sv.get("ping", "?")),
                    str(sv.get("fps", "?")),
                ])
            _tbl(story, svdata, [1.5*inch, 1.5*inch, 2.0*inch, 2.0*inch])

        badges = G.get("badges", [])
        if badges:
            story.append(Paragraph(f"GAME BADGES  ({len(badges)} total)", PDF_S["h2"]))
            bdata = [["Badge Name", "Awarded Count", "Description"]]
            for b in badges[:15]:
                awarded = b.get("statistics", {}).get("awardedCount", 0)
                bdesc   = (b.get("description", "") or "")[:60]
                bdata.append([b.get("name","?")[:35], f"{awarded:,}", bdesc])
            _tbl(story, bdata, [2.5*inch, 1.5*inch, 3.0*inch])

        if A.get("flags"):
            story.append(Paragraph("AUTOMATED FLAGS", PDF_S["h2"]))
            for f in A["flags"]:
                story.append(Paragraph(f"  ⚠ {f}", PDF_S["flag"]))
        if A.get("notes"):
            story.append(Paragraph("ANALYST NOTES", PDF_S["h2"]))
            for n in A["notes"]:
                story.append(Paragraph(f"  • {n}", PDF_S["body"]))

    # ── FOOTER ──
    story += [
        Spacer(1, 0.25*inch),
        HRFlowable(width="100%", thickness=1, color=C_BORDER),
        Paragraph(
            "NEXUS INTELLIGENCE BOT  ·  Data sourced from publicly available APIs only  "
            "·  For authorized investigative use only.",
            PDF_S["small"]
        ),
    ]
    doc.build(story)
    return buf.getvalue()



# ─────────────────────────────────────────────────────
#  ROBLOX GROUP & GAME API HELPERS
# ─────────────────────────────────────────────────────
async def fetch_all_affiliates(s, gid: str, rel_type: str) -> list:
    """Page through the affiliates API to get every entry, not just the first 10."""
    all_groups = []
    start = 0
    page_size = 100
    while True:
        j = await rbx_get(s,
            f"https://groups.roblox.com/v1/groups/{gid}/relationships/{rel_type}"
            f"?StartRowIndex={start}&MaxRows={page_size}")
        batch = j.get("relatedGroups", [])
        all_groups.extend(batch)
        # Stop if we got fewer than a full page (no more data)
        if len(batch) < page_size:
            break
        start += page_size
        # Safety cap at 1000
        if start >= 1000:
            break
    return all_groups

async def fetch_group_data(s, group_id):
    gid = str(group_id)

    async def safe(coro):
        try:
            return await asyncio.wait_for(coro, timeout=8)
        except Exception:
            return {}

    info, roles, wall, allies_preview, enemies_preview, games, thumb = await asyncio.gather(
        safe(rbx_get(s, f"https://groups.roblox.com/v1/groups/{gid}")),
        safe(rbx_get(s, f"https://groups.roblox.com/v1/groups/{gid}/roles")),
        safe(rbx_get(s, f"https://groups.roblox.com/v1/groups/{gid}/wall/posts?limit=10&sortOrder=Desc")),
        safe(rbx_get(s, f"https://groups.roblox.com/v1/groups/{gid}/relationships/allies?StartRowIndex=0&MaxRows=10")),
        safe(rbx_get(s, f"https://groups.roblox.com/v1/groups/{gid}/relationships/enemies?StartRowIndex=0&MaxRows=10")),
        safe(rbx_get(s, f"https://games.roblox.com/v2/groups/{gid}/games?accessFilter=Public&limit=10&sortOrder=Asc")),
        safe(rbx_get(s, f"https://thumbnails.roblox.com/v1/groups/icons?groupIds={gid}&size=420x420&format=Png")),
    )

    # Embed uses the preview (first 10). Full list fetched separately for PDF.
    allies_embed  = allies_preview.get("relatedGroups", [])
    enemies_embed = enemies_preview.get("relatedGroups", [])

    # Full paginated lists for PDF export
    allies_full, enemies_full = await asyncio.gather(
        fetch_all_affiliates(s, gid, "allies"),
        fetch_all_affiliates(s, gid, "enemies"),
    )

    icon_url = (thumb.get("data") or [{}])[0].get("imageUrl", "") if thumb.get("data") else ""
    return {
        "info":          info,
        "roles":         roles.get("roles", []),
        "wall":          wall.get("data", []),
        "shout":         info.get("shout"),
        "allies":        allies_embed,    # capped at 10, used by embeds
        "enemies":       enemies_embed,   # capped at 10, used by embeds
        "allies_full":   allies_full,     # full list, used by PDF
        "enemies_full":  enemies_full,    # full list, used by PDF
        "games":         games.get("data", []),
        "icon_url":      icon_url,
    }

async def resolve_group_name(s, name):
    j = await rbx_get(s, f"https://groups.roblox.com/v1/groups/search?keyword={name}&prioritizeExactMatch=true&limit=10")
    results = j.get("data", [])
    if results:
        return results[0].get("id")
    return None

async def fetch_game_data(s, universe_id):
    uid = str(universe_id)

    async def safe(coro):
        try:
            return await asyncio.wait_for(coro, timeout=8)
        except Exception:
            return {}

    details_wrap, votes, badges, servers, thumb = await asyncio.gather(
        safe(rbx_get(s, f"https://games.roblox.com/v1/games?universeIds={uid}")),
        safe(rbx_get(s, f"https://games.roblox.com/v1/games/{uid}/votes")),
        safe(rbx_get(s, f"https://badges.roblox.com/v1/universes/{uid}/badges?limit=20&sortOrder=Asc")),
        safe(rbx_get(s, f"https://games.roblox.com/v1/games/{uid}/servers/Public?limit=10")),
        safe(rbx_get(s, f"https://thumbnails.roblox.com/v1/games/icons?universeIds={uid}&returnPolicy=PlaceHolder&size=512x512&format=Png")),
    )

    details  = (details_wrap.get("data") or [{}])[0] if details_wrap.get("data") else {}
    icon_url = (thumb.get("data") or [{}])[0].get("imageUrl", "") if thumb.get("data") else ""
    return {
        "details":  details,
        "votes":    votes,
        "badges":   badges.get("data", []),
        "servers":  servers.get("data", []),
        "icon_url": icon_url,
    }

async def resolve_game_id(s, query):
    """
    Resolve a game to its universe ID.
    Accepts: universe ID (number), place ID (number), roblox.com/games/URL, or name search.
    """
    query = query.strip()

    # Direct numeric ID — could be universe ID or place ID, try both
    if query.isdigit():
        uid = int(query)
        # Verify it's a valid universe ID first
        j = await rbx_get(s, f"https://games.roblox.com/v1/games?universeIds={uid}")
        if j.get("data"):
            return uid
        # Try treating it as a place ID and convert
        j2 = await rbx_get(s, f"https://apis.roblox.com/universes/v1/places/{uid}/universe")
        if j2.get("universeId"):
            return j2["universeId"]
        return uid  # Return as-is, let the caller handle failure

    # Full or partial roblox.com URL
    m = re.search(r"roblox\.com/games/(\d+)", query)
    if m:
        place_id = int(m.group(1))
        j = await rbx_get(s, f"https://apis.roblox.com/universes/v1/places/{place_id}/universe")
        return j.get("universeId")

    # Name search — use the catalog/games search API
    import urllib.parse
    encoded = urllib.parse.quote(query)

    # Try the games search endpoint
    j = await rbx_get(s, f"https://games.roblox.com/v1/games/list?keyword={encoded}&maxRows=6&sortToken=&gameFilter=0")
    games = j.get("games", [])
    if games:
        # Return the first result's universe ID
        return games[0].get("universeId")

    # Fallback: game search via the main search API
    j2 = await rbx_get(s, f"https://www.roblox.com/search/getjsonforuniverses?keyword={encoded}&maxRows=1")
    results = j2.get("data") or []
    if results:
        return results[0].get("universeId")

    return None

# ─────────────────────────────────────────────────────
#  GROUP ANALYSIS
# ─────────────────────────────────────────────────────
def analyse_group(G):
    info    = G.get("info", {})
    roles   = G.get("roles", [])
    wall    = G.get("wall", [])
    allies  = G.get("allies", [])
    enemies = G.get("enemies", [])
    games   = G.get("games", [])
    flags   = []
    notes   = []
    now     = datetime.now(timezone.utc)

    member_count = info.get("memberCount", 0)
    created_raw  = info.get("created", "")
    created_str  = "Unknown"
    age_days     = 0
    if created_raw:
        try:
            dt          = datetime.fromisoformat(created_raw.replace("Z", "+00:00"))
            age_days    = (now - dt).days
            created_str = dt.strftime("%B %d, %Y")
        except Exception:
            pass

    total_roles  = len(roles)
    owner_role   = next((r for r in roles if r.get("rank", 0) == 255), None)
    high_roles   = [r for r in roles if 200 <= r.get("rank", 0) < 255]
    top_role_name = owner_role.get("name", "Unknown") if owner_role else "Unknown"
    non_guest    = [r for r in roles if r.get("rank", 0) > 0]
    biggest_role = max(non_guest, key=lambda r: r.get("memberCount", 0), default={})

    if member_count < 100 and age_days > 180:
        flags.append("Low member count for age — possibly inactive")
    if total_roles > 20:
        flags.append(f"High role count ({total_roles}) — complex hierarchy")
    if not info.get("description", "").strip():
        flags.append("No group description set")
    if info.get("isLocked"):
        flags.append("Group is locked")
        notes.append("Group is locked — joins disabled.")
    if enemies:
        notes.append(f"Has {len(enemies)} declared enemy group(s).")
    if allies:
        notes.append(f"Allied with {len(allies)} group(s).")

    last_post = "No activity"
    if wall:
        raw = wall[0].get("updated", "") or wall[0].get("created", "")
        try:
            wp        = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            last_post = wp.strftime("%Y-%m-%d %H:%M UTC")
        except Exception:
            last_post = raw[:19] if raw else "Unknown"

    maturity_score = min(100, int((age_days / 1825) * 100))
    size_score     = min(100, int((member_count / 10000) * 100))
    activity_score = min(100, 50 + (len(wall) * 5) + (len(games) * 10))
    overall        = int(maturity_score * 0.3 + size_score * 0.4 + activity_score * 0.3)

    if not notes:
        notes.append("No notable anomalies detected.")

    return {
        "created_str":    created_str,
        "age_days":       age_days,
        "member_count":   member_count,
        "total_roles":    total_roles,
        "top_role_name":  top_role_name,
        "high_roles":     high_roles,
        "biggest_role":   biggest_role,
        "wall_active":    len(wall) > 0,
        "last_post":      last_post,
        "ally_count":     len(allies),
        "enemy_count":    len(enemies),
        "game_count":     len(games),
        "flags":          flags,
        "notes":          notes,
        "maturity":       maturity_score,
        "size":           size_score,
        "activity":       activity_score,
        "overall":        overall,
    }

# ─────────────────────────────────────────────────────
#  GAME ANALYSIS
# ─────────────────────────────────────────────────────
def analyse_game(G):
    details  = G.get("details", {})
    votes    = G.get("votes", {})
    badges   = G.get("badges", [])
    servers  = G.get("servers", [])
    flags    = []
    notes    = []
    now      = datetime.now(timezone.utc)

    visits   = details.get("visits", 0)
    playing  = details.get("playing", 0)
    favs     = details.get("favoritedCount", 0)
    up_votes = votes.get("upVotes", 0)
    dn_votes = votes.get("downVotes", 0)
    total_v  = up_votes + dn_votes
    like_pct = round((up_votes / total_v) * 100, 1) if total_v > 0 else 0

    created_raw = details.get("created", "")
    updated_raw = details.get("updated", "")
    created_str = "Unknown"
    updated_str = "Unknown"
    age_days    = 0

    if created_raw:
        try:
            dt          = datetime.fromisoformat(created_raw.replace("Z", "+00:00"))
            age_days    = (now - dt).days
            created_str = dt.strftime("%B %d, %Y")
        except Exception:
            pass
    if updated_raw:
        try:
            du          = datetime.fromisoformat(updated_raw.replace("Z", "+00:00"))
            updated_str = du.strftime("%B %d, %Y")
            if (now - du).days > 365:
                flags.append(f"Not updated in {(now - du).days} days — possibly abandoned")
        except Exception:
            pass

    active_servers  = len(servers)
    total_players   = sum(sv.get("playing", 0) for sv in servers)
    max_players     = details.get("maxPlayers", 0)
    avg_server_fill = 0
    if servers and max_players > 0:
        fills = [sv.get("playing", 0) / max_players for sv in servers]
        avg_server_fill = round(sum(fills) / len(fills) * 100) if fills else 0

    if like_pct < 50 and total_v > 100:
        flags.append(f"Low like ratio ({like_pct}%) — negative reception")
    if visits > 1_000_000 and playing < 10:
        flags.append("High visits but near-zero concurrent players — likely dead")
    if not details.get("description", "").strip():
        flags.append("No game description set")
    if details.get("isCopylocked"):
        flags.append("Game is copylocked")

    popularity = min(100, int((visits / 1_000_000) * 50) + min(50, playing // 10))
    quality    = min(100, int(like_pct))
    engagement = min(100, int((favs / max(visits, 1)) * 10000))
    overall    = int(popularity * 0.4 + quality * 0.4 + engagement * 0.2)

    if like_pct >= 80:
        notes.append("Strong positive reception from players.")
    elif like_pct >= 60:
        notes.append("Mixed but generally positive reception.")
    else:
        notes.append("Negative or polarized player reception.")

    if playing > 1000:
        notes.append(f"Highly active with {playing:,} concurrent players.")
    elif playing > 0:
        notes.append(f"{playing} concurrent players at time of lookup.")
    else:
        notes.append("No concurrent players detected at time of lookup.")

    return {
        "created_str":     created_str,
        "updated_str":     updated_str,
        "age_days":        age_days,
        "visits":          visits,
        "playing":         playing,
        "favs":            favs,
        "up_votes":        up_votes,
        "dn_votes":        dn_votes,
        "like_pct":        like_pct,
        "total_votes":     total_v,
        "active_servers":  active_servers,
        "total_players":   total_players,
        "avg_server_fill": avg_server_fill,
        "max_players":     max_players,
        "badge_count":     len(badges),
        "flags":           flags,
        "notes":           notes,
        "popularity":      popularity,
        "quality":         quality,
        "engagement":      engagement,
        "overall":         overall,
    }

# ─────────────────────────────────────────────────────
#  /group_lookup
# ─────────────────────────────────────────────────────
@tree.command(name="group_lookup", description="Deep OSINT analysis on a Roblox group")
@app_commands.describe(group="Group name or group ID")
async def group_lookup(interaction: discord.Interaction, group: str):
    if not get_session(interaction.user.id):
        await interaction.response.send_modal(AuthModal(lambda i, k: _glookup(i, group)))
        return
    await thinking_msg(interaction, f"Pulling intelligence on group **{group}**...")
    await _glookup(interaction, group)

async def _glookup(interaction: discord.Interaction, group: str):
    async with aiohttp.ClientSession() as s:
        gid = int(group.strip()) if group.strip().isdigit() else await resolve_group_name(s, group)
        if not gid:
            await edit_original(interaction, embed=err_embed(f"Could not find group: `{group}`"))
            return
        G = await fetch_group_data(s, gid)

    info = G.get("info", {})
    if not info:
        await edit_original(interaction, embed=err_embed(f"No data found for group ID `{gid}`"))
        return

    A       = analyse_group(G)
    roles   = G.get("roles", [])
    wall    = G.get("wall", [])
    allies  = G.get("allies", [])
    enemies = G.get("enemies", [])
    games   = G.get("games", [])
    shout   = G.get("shout")
    owner   = info.get("owner", {})
    pages   = []

    # PAGE 1 — BRIEF
    p1 = nexus_embed("NEXUS \u00b7 Group Brief", color=SLATE)
    if G.get("icon_url"):
        p1.set_thumbnail(url=G["icon_url"])
    gname = info.get("name", "?")
    p1.add_field(name="\U0001f3af Target",
        value=f"**{gname}**  (`{gid}`)\nhttps://www.roblox.com/groups/{gid}",
        inline=False)
    p1.add_field(name="\U0001f4ca Scoreboard", value=(
        "Overall     " + score_bar(A["overall"]) + "\n"
        "Maturity    " + score_bar(A["maturity"]) + "\n"
        "Size        " + score_bar(A["size"]) + "\n"
        "Activity    " + score_bar(A["activity"])
    ), inline=False)
    p1.add_field(name="\U0001f52c Key Signals", value=(
        f"Members: **{A['member_count']:,}** \u00b7 "
        f"Roles: **{A['total_roles']}** \u00b7 "
        f"Age: **{A['age_days']:,}d**\n"
        f"Allies: **{A['ally_count']}** \u00b7 "
        f"Enemies: **{A['enemy_count']}** \u00b7 "
        f"Public games: **{A['game_count']}**"
    ), inline=False)
    p1.add_field(name="\U0001f9e0 Analyst Notes",
        value="\n".join(f"\u2022 {n}" for n in A["notes"]), inline=False)
    if A["flags"]:
        p1.add_field(name="\U0001f6a9 Flags",
            value="\n".join(f"\u2022 \u26a0\ufe0f {f}" for f in A["flags"]), inline=False)
    pages.append(p1)

    # PAGE 2 — IDENTITY
    p2 = nexus_embed("NEXUS \u00b7 Group Identity", color=TEAL)
    if G.get("icon_url"):
        p2.set_thumbnail(url=G["icon_url"])
    p2.add_field(name="\U0001f3db\ufe0f Identity", value=(
        f"Name: **{gname}**\n"
        f"Group ID: `{gid}`\n"
        f"Created: **{A['created_str']}** ({A['age_days']:,}d ago)\n"
        f"Members: **{A['member_count']:,}**\n"
        f"Public entry: {'yes' if info.get('publicEntryAllowed') else 'no'} \u00b7 "
        f"Locked: {'yes' if info.get('isLocked') else 'no'} \u00b7 "
        f"Verified: {'yes' if info.get('hasVerifiedBadge') else 'no'}"
    ), inline=False)
    if owner:
        p2.add_field(name="\U0001f451 Owner",
            value=f"**{owner.get('username','?')}** (`{owner.get('userId','?')}`)\nhttps://www.roblox.com/users/{owner.get('userId','?')}/profile",
            inline=False)
    desc = info.get("description", "").strip()
    p2.add_field(name="\U0001f4dd Description",
        value=desc[:1000] if desc else "*No description set*", inline=False)
    if shout and shout.get("body"):
        shout_poster = shout.get("poster", {})
        shout_ts     = (shout.get("updated", "") or shout.get("created", ""))[:10]
        p2.add_field(name="\U0001f4e2 Group Shout",
            value=f"**{shout.get('body','')[:300]}**\n\u2014 {shout_poster.get('username','?')} \u00b7 {shout_ts}",
            inline=False)
    pages.append(p2)

    # PAGE 3 — ROLES
    p3 = nexus_embed("NEXUS \u00b7 Role Structure", color=PURPLE)
    biggest_name = A["biggest_role"].get("name", "?") if A["biggest_role"] else "?"
    biggest_mc   = A["biggest_role"].get("memberCount", 0) if A["biggest_role"] else 0
    p3.add_field(name="\U0001f4cb Overview", value=(
        f"Total roles: **{A['total_roles']}**\n"
        f"High-authority (rank \u2265200): **{len(A['high_roles'])}**\n"
        f"Largest role: **{biggest_name}** ({biggest_mc:,} members)\n"
        f"Owner role: **{A['top_role_name']}**"
    ), inline=False)
    if roles:
        sorted_roles = sorted(roles, key=lambda x: x.get("rank", 0), reverse=True)
        role_lines   = [
            f"`{r.get('rank',0):>3}` **{r.get('name','?')}** \u2014 {r.get('memberCount',0):,} members"
            for r in sorted_roles
        ]
        p3.add_field(name=f"\U0001f396\ufe0f All Roles ({len(roles)} total)",
            value="\n".join(role_lines[:20]) or "*None*", inline=False)
        if len(role_lines) > 20:
            p3.add_field(name="\u2026continued",
                value="\n".join(role_lines[20:40]), inline=False)
    pages.append(p3)

    # PAGE 4 — WALL & ACTIVITY
    p4 = nexus_embed("NEXUS \u00b7 Wall & Activity", color=GREEN)
    p4.add_field(name="\U0001f4ca Activity Snapshot", value=(
        f"Last wall post: **{A['last_post']}**\n"
        f"Wall posts loaded: **{len(wall)}**\n"
        f"Public games: **{A['game_count']}**"
    ), inline=False)
    if wall:
        wlines = []
        for post in wall[:6]:
            poster = post.get("poster") or {}
            body   = (post.get("body", "") or "")[:100].replace("\n", " ")
            ts     = (post.get("updated", "") or post.get("created", ""))[:10]
            wlines.append(f"**{poster.get('username','?')}** \u00b7 {ts}\n> {body}")
        p4.add_field(name="\U0001f5d2\ufe0f Recent Wall Posts",
            value="\n\n".join(wlines) or "*No posts*", inline=False)
    if games:
        glines = [
            f"\u2022 **{g.get('name','?')}** \u2014 Visits: **{g.get('placeVisits',0):,}** \u00b7 Playing: **{g.get('playing',0)}**"
            for g in games[:6]
        ]
        p4.add_field(name=f"\U0001f3ae Group Games ({len(games)} found)",
            value="\n".join(glines), inline=False)
    pages.append(p4)

    # PAGE 5 — AFFILIATIONS
    p5 = nexus_embed("NEXUS \u00b7 Affiliations", color=GOLD)
    if allies:
        alines = [
            f"\u2022 **{a.get('name','?')}** (`{a.get('id','?')}`) \u2014 {a.get('memberCount',0):,} members"
            for a in allies[:10]
        ]
        p5.add_field(name=f"\U0001f91d Allied Groups ({len(allies)})",
            value="\n".join(alines), inline=False)
    else:
        p5.add_field(name="\U0001f91d Allied Groups", value="*None found*", inline=False)
    if enemies:
        elines = [
            f"\u2022 **{e.get('name','?')}** (`{e.get('id','?')}`) \u2014 {e.get('memberCount',0):,} members"
            for e in enemies[:10]
        ]
        p5.add_field(name=f"\u2694\ufe0f Enemy Groups ({len(enemies)})",
            value="\n".join(elines), inline=False)
    else:
        p5.add_field(name="\u2694\ufe0f Enemy Groups", value="*None found*", inline=False)
    pages.append(p5)

    store_report(interaction.user.id, {
        "type": "group_lookup", "info": info, "extra": G,
        "analysis": A, "subject": gname,
    })
    await edit_original(interaction, embed=pages[0], view=PageView(pages))

# ─────────────────────────────────────────────────────
#  /game_lookup
# ─────────────────────────────────────────────────────
@tree.command(name="game_lookup", description="Deep analysis on a Roblox game")
@app_commands.describe(game="Game name, universe ID, or Roblox game URL")
async def game_lookup(interaction: discord.Interaction, game: str):
    if not get_session(interaction.user.id):
        await interaction.response.send_modal(AuthModal(lambda i, k: _gamelookup(i, game)))
        return
    await thinking_msg(interaction, f"Pulling intelligence on **{game}**...")
    await _gamelookup(interaction, game)

async def _gamelookup(interaction: discord.Interaction, game: str):
    async with aiohttp.ClientSession() as s:
        uid = await resolve_game_id(s, game)
        if not uid:
            await edit_original(interaction, embed=err_embed(
                f"Could not find game: `{game}`\n\n"
                f"**Tips:**\n"
                f"• Use the **Universe ID** (found in Creator Dashboard)\n"
                f"• Paste the full **roblox.com/games/XXXXXXX** URL\n"
                f"• Try a more exact game name"))
            return
        G = await fetch_game_data(s, uid)

    details = G.get("details", {})
    if not details:
        await edit_original(interaction, embed=err_embed(f"No data found for game ID `{uid}`"))
        return

    A       = analyse_game(G)
    badges  = G.get("badges", [])
    servers = G.get("servers", [])
    creator = details.get("creator", {})
    cname   = creator.get("name", "?")
    ctype   = creator.get("type", "?")
    cid     = creator.get("id", "?")
    curl    = (f"https://www.roblox.com/groups/{cid}"
               if ctype == "Group"
               else f"https://www.roblox.com/users/{cid}/profile")
    pages   = []

    # PAGE 1 — BRIEF
    p1 = nexus_embed("NEXUS \u00b7 Game Brief", color=SLATE)
    if G.get("icon_url"):
        p1.set_thumbnail(url=G["icon_url"])
    gname    = details.get("name", "?")
    root_pid = details.get("rootPlaceId", "?")
    p1.add_field(name="\U0001f3af Target",
        value=f"**{gname}**  (`{uid}`)\nhttps://www.roblox.com/games/{root_pid}",
        inline=False)
    p1.add_field(name="\U0001f4ca Scoreboard", value=(
        "Overall     " + score_bar(A["overall"]) + "\n"
        "Popularity  " + score_bar(A["popularity"]) + "\n"
        "Reception   " + score_bar(A["quality"]) + "\n"
        "Engagement  " + score_bar(A["engagement"])
    ), inline=False)
    p1.add_field(name="\U0001f52c Key Signals", value=(
        f"Visits: **{A['visits']:,}** \u00b7 "
        f"Playing: **{A['playing']:,}** \u00b7 "
        f"Favorites: **{A['favs']:,}**\n"
        f"Likes: **{A['up_votes']:,}** \u00b7 "
        f"Dislikes: **{A['dn_votes']:,}** \u00b7 "
        f"Approval: **{A['like_pct']}%**\n"
        f"Badges: **{A['badge_count']}** \u00b7 "
        f"Active servers: **{A['active_servers']}**"
    ), inline=False)
    p1.add_field(name="\U0001f9e0 Analyst Notes",
        value="\n".join(f"\u2022 {n}" for n in A["notes"]), inline=False)
    if A["flags"]:
        p1.add_field(name="\U0001f6a9 Flags",
            value="\n".join(f"\u2022 \u26a0\ufe0f {f}" for f in A["flags"]), inline=False)
    pages.append(p1)

    # PAGE 2 — IDENTITY
    p2 = nexus_embed("NEXUS \u00b7 Game Identity", color=TEAL)
    if G.get("icon_url"):
        p2.set_thumbnail(url=G["icon_url"])
    p2.add_field(name="\U0001f3ae Details", value=(
        f"Universe ID: `{uid}`\n"
        f"Root Place ID: `{root_pid}`\n"
        f"Genre: **{details.get('genre','?')}**\n"
        f"Max Players: **{A['max_players']}**\n"
        f"Created: **{A['created_str']}** ({A['age_days']:,}d ago)\n"
        f"Last Updated: **{A['updated_str']}**\n"
        f"Copylocked: {'yes' if details.get('isCopylocked') else 'no'}"
    ), inline=False)
    icon = "\U0001f465" if ctype == "Group" else "\U0001f464"
    p2.add_field(name=f"{icon} Creator",
        value=f"**{cname}** ({ctype})\n{curl}", inline=False)
    desc = details.get("description", "").strip()
    p2.add_field(name="\U0001f4dd Description",
        value=desc[:1000] if desc else "*No description set*", inline=False)
    pages.append(p2)

    # PAGE 3 — STATS & SERVERS
    p3 = nexus_embed("NEXUS \u00b7 Stats & Reception", color=PURPLE)
    p3.add_field(name="\U0001f4c8 Performance", value=(
        f"Total visits:    **{A['visits']:,}**\n"
        f"Concurrent now:  **{A['playing']:,}**\n"
        f"Favorited:       **{A['favs']:,}**\n"
        f"Visit/Fav ratio: **{round(A['visits']/max(A['favs'],1),1)}:1**"
    ), inline=True)
    p3.add_field(name="\U0001f44d Reception", value=(
        f"Upvotes:     **{A['up_votes']:,}**\n"
        f"Downvotes:   **{A['dn_votes']:,}**\n"
        f"Approval:    **{A['like_pct']}%**\n"
        f"Total votes: **{A['total_votes']:,}**"
    ), inline=True)
    p3.add_field(name="\u200b", value="\u200b", inline=True)
    if servers:
        p3.add_field(name="\U0001f5a5\ufe0f Server Snapshot", value=(
            f"Active servers: **{A['active_servers']}**\n"
            f"Players across servers: **{A['total_players']}**\n"
            f"Avg server fill: **{A['avg_server_fill']}%**\n"
            f"Max per server: **{A['max_players']}**"
        ), inline=False)
        sv_lines = [
            f"\u2022 **{sv.get('playing',0)}/{sv.get('maxPlayers', A['max_players'])}** players \u00b7 Ping: {sv.get('ping','?')}ms \u00b7 FPS: {sv.get('fps','?')}"
            for sv in servers[:6]
        ]
        p3.add_field(name="\U0001f4e1 Live Servers (sample)",
            value="\n".join(sv_lines), inline=False)
    pages.append(p3)

    # PAGE 4 — BADGES
    p4 = nexus_embed("NEXUS \u00b7 Game Badges", color=GOLD)
    p4.add_field(name="\U0001f3c5 Overview",
        value=f"Total badges: **{A['badge_count']}**", inline=False)
    if badges:
        blines = []
        for b in badges[:12]:
            awarded = b.get("statistics", {}).get("awardedCount", 0)
            bdesc   = (b.get("description", "") or "No description")[:80]
            blines.append(
                f"\u2022 **{b.get('name','?')}** \u2014 awarded **{awarded:,}** times\n  _{bdesc}_"
            )
        p4.add_field(name=f"\U0001f396\ufe0f Badge List (top {min(12,len(badges))} of {len(badges)})",
            value="\n".join(blines) or "*None*", inline=False)
    else:
        p4.add_field(name="\U0001f396\ufe0f Badges", value="*No badges found for this game.*", inline=False)
    pages.append(p4)

    store_report(interaction.user.id, {
        "type": "game_lookup", "details": details, "extra": G,
        "analysis": A, "subject": gname,
    })
    await edit_original(interaction, embed=pages[0], view=PageView(pages))


# ─────────────────────────────────────────────────────
#  BOT EVENTS
# ─────────────────────────────────────────────────────
@bot.event
async def on_ready():
    db_init()
    try:
        synced = await tree.sync()
        print(f"[SYNC] Synced {len(synced)} command(s) globally.")
    except Exception as e:
        print(f"[WARN] Sync failed: {e}")
    print(f"""
╔══════════════════════════════════════════╗
║        NEXUS BOT v2.0  —  Online        ║
║  {str(bot.user):<40}║
║  Guilds: {len(bot.guilds):<32}║
╚══════════════════════════════════════════╝
""")

if __name__ == "__main__":
    db_init()
    bot.run(BOT_TOKEN)