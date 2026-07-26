"""Sherlock Wrapper — username OSINT across 400+ social platforms.

Runs sherlock via subprocess if installed.
Falls back to HTTP-based username checking on 20+ popular platforms.
"""

import time
import re
import json
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from .base import BaseTool, ToolResult
from ..core.logger import logger
from ..core.ratelimit import get_limiter


# ──────────────────────────────────────────────────────────────────────
# Platform definitions for fallback HTTP-based username checking
# Each entry: (platform_name, url_template, detection_method, not_found_indicators)
# ──────────────────────────────────────────────────────────────────────
FALLBACK_PLATFORMS = [
    # ── Developer & Code ──
    {
        "name": "GitHub",
        "url": "https://github.com/{username}",
        "method": "status",
        "not_found": ["Not Found", "doesn't exist", "page not found"],
    },
    {
        "name": "GitLab",
        "url": "https://gitlab.com/{username}",
        "method": "status",
        "not_found": ["Explore GitLab", "page not found", "doesn't exist"],
    },
    {
        "name": "Bitbucket",
        "url": "https://bitbucket.org/{username}/",
        "method": "status",
        "not_found": ["Repository not found", "page not found"],
    },
    {
        "name": "StackOverflow",
        "url": "https://stackoverflow.com/users?tab=Accounts&SearchTerm={username}",
        "method": "content",
        "not_found": ["0 results", "no users found"],
        "found_indicators": ["user-info", "user-details"],
    },
    {
        "name": "Dev.to",
        "url": "https://dev.to/{username}",
        "method": "status",
        "not_found": ["doesn't exist", "page not found"],
    },
    {
        "name": "CodePen",
        "url": "https://codepen.io/{username}",
        "method": "status",
        "not_found": ["404", "doesn't exist"],
    },
    {
        "name": "Replit",
        "url": "https://replit.com/@{username}",
        "method": "status",
        "not_found": ["404", "not found"],
    },
    {
        "name": "Docker Hub",
        "url": "https://hub.docker.com/u/{username}",
        "method": "status",
        "not_found": ["404", "page not found"],
    },

    # ── Social Media ──
    {
        "name": "Twitter/X",
        "url": "https://x.com/{username}",
        "method": "status",
        "not_found": ["doesn't exist", "this account doesn't exist", "page doesn't exist"],
    },
    {
        "name": "Instagram",
        "url": "https://www.instagram.com/{username}/",
        "method": "content",
        "not_found": ["Sorry, this page isn't available", "page not found"],
        "found_indicators": ["profilePage", "biography"],
    },
    {
        "name": "Reddit",
        "url": "https://www.reddit.com/user/{username}",
        "method": "status",
        "not_found": ["page not found", "Sorry, nobody on Reddit goes by that name"],
    },
    {
        "name": "TikTok",
        "url": "https://www.tiktok.com/@{username}",
        "method": "content",
        "not_found": ["Couldn't find this account", "couldn't find this account"],
        "found_indicators": ["user-info", "uniqueId"],
    },
    {
        "name": "Pinterest",
        "url": "https://www.pinterest.com/{username}/",
        "method": "status",
        "not_found": ["page not found", "404"],
    },
    {
        "name": "Tumblr",
        "url": "https://{username}.tumblr.com",
        "method": "status",
        "not_found": ["There's nothing here", "not found"],
    },
    {
        "name": "Medium",
        "url": "https://medium.com/@{username}",
        "method": "status",
        "not_found": ["404", "page not found", "out of nothing"],
    },
    {
        "name": "Quora",
        "url": "https://www.quora.com/profile/{username}",
        "method": "status",
        "not_found": ["Page Not Found", "404"],
    },

    # ── Video & Streaming ──
    {
        "name": "YouTube",
        "url": "https://www.youtube.com/@{username}",
        "method": "content",
        "not_found": ["404", "This page isn't available", "does not exist"],
        "found_indicators": ["channel-header", "subscriberCount"],
    },
    {
        "name": "Twitch",
        "url": "https://www.twitch.tv/{username}",
        "method": "content",
        "not_found": ["Sorry. Unless you've got a time machine", "page not found"],
        "found_indicators": ["channel-info", "tw-channel"],
    },
    {
        "name": "Vimeo",
        "url": "https://vimeo.com/{username}",
        "method": "status",
        "not_found": ["not found", "404"],
    },
    {
        "name": "Dailymotion",
        "url": "https://www.dailymotion.com/{username}",
        "method": "status",
        "not_found": ["not found", "404"],
    },

    # ── Professional ──
    {
        "name": "LinkedIn",
        "url": "https://www.linkedin.com/in/{username}",
        "method": "content",
        "not_found": ["page not found", "this page doesn't exist", "profile not found"],
        "found_indicators": ["profile-section", "pv-top-card"],
    },

    # ── Security & Hacking ──
    {
        "name": "HackerOne",
        "url": "https://hackerone.com/{username}",
        "method": "status",
        "not_found": ["not found", "404"],
    },
    {
        "name": "Bugcrowd",
        "url": "https://bugcrowd.com/{username}",
        "method": "status",
        "not_found": ["not found", "404"],
    },
    {
        "name": "TryHackMe",
        "url": "https://tryhackme.com/p/{username}",
        "method": "status",
        "not_found": ["not found", "404"],
    },
    {
        "name": "HackTheBox",
        "url": "https://app.hackthebox.com/users/{username}",
        "method": "status",
        "not_found": ["not found", "404"],
    },

    # ── Communication ──
    {
        "name": "Telegram",
        "url": "https://t.me/{username}",
        "method": "content",
        "not_found": ["If you have <strong>Telegram</strong>, you can contact"],
        "found_indicators": ["tgme_page_description", "tgme_page_title"],
    },
    {
        "name": "Keybase",
        "url": "https://keybase.io/{username}",
        "method": "status",
        "not_found": ["not found", "404"],
    },

    # ── Music ──
    {
        "name": "SoundCloud",
        "url": "https://soundcloud.com/{username}",
        "method": "status",
        "not_found": ["We can't find that user", "not found"],
    },
    {
        "name": "Spotify",
        "url": "https://open.spotify.com/user/{username}",
        "method": "status",
        "not_found": ["not found", "404"],
    },

    # ── Design & Creative ──
    {
        "name": "Behance",
        "url": "https://www.behance.net/{username}",
        "method": "status",
        "not_found": ["404", "not found"],
    },
    {
        "name": "Dribbble",
        "url": "https://dribbble.com/{username}",
        "method": "status",
        "not_found": ["404", "not found", "not a member"],
    },
    {
        "name": "DeviantArt",
        "url": "https://www.deviantart.com/{username}",
        "method": "status",
        "not_found": ["does not exist", "404", "not found"],
    },
    {
        "name": "Flickr",
        "url": "https://www.flickr.com/people/{username}/",
        "method": "status",
        "not_found": ["member not found", "404"],
    },

    # ── Miscellaneous ──
    {
        "name": "Patreon",
        "url": "https://www.patreon.com/{username}",
        "method": "status",
        "not_found": ["404", "not found"],
    },
    {
        "name": "Gravatar",
        "url": "https://gravatar.com/{username}",
        "method": "status",
        "not_found": ["Profile not found", "not found"],
    },
    {
        "name": "About.me",
        "url": "https://about.me/{username}",
        "method": "status",
        "not_found": ["not found", "404"],
    },
    {
        "name": "Linktree",
        "url": "https://linktr.ee/{username}",
        "method": "content",
        "not_found": ["Nothing to see here", "page not found"],
        "found_indicators": ["profile-header", "linktree"],
    },
    {
        "name": "Roblox",
        "url": "https://www.roblox.com/users/profile?username={username}",
        "method": "status",
        "not_found": ["not found", "404"],
    },
    {
        "name": "Steam",
        "url": "https://steamcommunity.com/id/{username}",
        "method": "content",
        "not_found": ["The specified profile could not be found", "profile could not be found"],
        "found_indicators": ["profile_page", "persona_name"],
    },

    # ── Social Media (expanded) ──
    {
        "name": "Facebook",
        "url": "https://www.facebook.com/{username}",
        "method": "content",
        "not_found": ["page isn't available", "content isn't available", "page not found"],
        "found_indicators": ["profile", "friends"],
    },
    {
        "name": "TikTok",
        "url": "https://www.tiktok.com/@{username}",
        "method": "status",
        "not_found": ["couldn't find this account"],
        "found_indicators": ["videos", "followers"],
    },
    {
        "name": "Snapchat",
        "url": "https://www.snapchat.com/add/{username}",
        "method": "status",
        "not_found": ["not found"],
        "found_indicators": ["snapcode"],
    },
    {
        "name": "Tumblr",
        "url": "https://{username}.tumblr.com",
        "method": "status",
        "not_found": ["not found", "There's nothing here"],
        "found_indicators": ["posts", "blog"],
    },
    {
        "name": "Flickr",
        "url": "https://www.flickr.com/people/{username}",
        "method": "content",
        "not_found": ["member not found"],
        "found_indicators": ["photostream"],
    },
    {
        "name": "Vimeo",
        "url": "https://vimeo.com/{username}",
        "method": "content",
        "not_found": ["does not exist", "not found"],
        "found_indicators": ["videos", "profile"],
    },
    {
        "name": "Mastodon",
        "url": "https://mastodon.social/@{username}",
        "method": "status",
        "not_found": ["not found", "is not available"],
        "found_indicators": ["profile", "statuses"],
    },
    {
        "name": "Bluesky",
        "url": "https://bsky.app/profile/{username}.bsky.social",
        "method": "status",
        "not_found": ["not found"],
        "found_indicators": ["posts", "followers"],
    },
    {
        "name": "Threads",
        "url": "https://www.threads.net/@{username}",
        "method": "content",
        "not_found": ["page isn't available"],
        "found_indicators": ["posts", "followers"],
    },
    {
        "name": "Minds",
        "url": "https://www.minds.com/{username}",
        "method": "status",
        "not_found": ["not found"],
        "found_indicators": ["channel"],
    },
    {
        "name": "Gab",
        "url": "https://gab.com/{username}",
        "method": "status",
        "not_found": ["doesn't exist"],
        "found_indicators": ["profile", "posts"],
    },
    {
        "name": "Truth Social",
        "url": "https://truthsocial.com/@{username}",
        "method": "status",
        "not_found": ["not found"],
        "found_indicators": ["profile"],
    },

    # ── Professional ──
    {
        "name": "LinkedIn",
        "url": "https://www.linkedin.com/in/{username}",
        "method": "content",
        "not_found": ["page not found", "this page doesn't exist"],
        "found_indicators": ["profile", "experience"],
    },
    {
        "name": "Indeed",
        "url": "https://www.indeed.com/r/{username}",
        "method": "status",
        "not_found": ["not found"],
        "found_indicators": ["resume"],
    },
    {
        "name": "Glassdoor",
        "url": "https://www.glassdoor.com/profile/{username}",
        "method": "status",
        "not_found": ["not found"],
        "found_indicators": ["profile"],
    },
    {
        "name": "Behance",
        "url": "https://www.behance.net/{username}",
        "method": "content",
        "not_found": ["404"],
        "found_indicators": ["projects", "gallery"],
    },
    {
        "name": "Dribbble",
        "url": "https://dribbble.com/{username}",
        "method": "content",
        "not_found": ["not found", "404"],
        "found_indicators": ["shots", "likes"],
    },
    {
        "name": "AngelList",
        "url": "https://angel.co/u/{username}",
        "method": "status",
        "not_found": ["not found"],
        "found_indicators": ["profile"],
    },
    {
        "name": "Crunchbase",
        "url": "https://www.crunchbase.com/person/{username}",
        "method": "status",
        "not_found": ["not found"],
        "found_indicators": ["profile"],
    },

    # ── Gaming ──
    {
        "name": "Twitch",
        "url": "https://www.twitch.tv/{username}",
        "method": "content",
        "not_found": ["does not exist", "couldn't find"],
        "found_indicators": ["channel", "videos"],
    },
    {
        "name": "Discord",
        "url": "https://discord.com/users/{username}",
        "method": "status",
        "not_found": ["not found"],
        "found_indicators": ["profile"],
    },
    {
        "name": "Roblox",
        "url": "https://www.roblox.com/user.aspx?username={username}",
        "method": "status",
        "not_found": ["not found"],
        "found_indicators": ["profile"],
    },
    {
        "name": "Minecraft",
        "url": "https://namemc.com/profile/{username}",
        "method": "content",
        "not_found": ["not found"],
        "found_indicators": ["profile", "skins"],
    },
    {
        "name": "Riot Games",
        "url": "https://tracker.gg/valorant/profile/riot/{username}/overview",
        "method": "status",
        "not_found": ["not found"],
        "found_indicators": ["profile"],
    },
    {
        "name": "Valorant",
        "url": "https://tracker.gg/valorant/profile/riot/{username}/overview",
        "method": "status",
        "not_found": ["not found"],
        "found_indicators": ["stats"],
    },
    {
        "name": "Epic Games",
        "url": "https://fortnitetracker.com/profile/all/{username}",
        "method": "content",
        "not_found": ["not found"],
        "found_indicators": ["profile"],
    },
    {
        "name": "Xbox",
        "url": "https://www.xboxgamertag.com/search/{username}",
        "method": "content",
        "not_found": ["not found"],
        "found_indicators": ["gamertag"],
    },

    # ── Coding ──
    {
        "name": "GitLab",
        "url": "https://gitlab.com/{username}",
        "method": "status",
        "not_found": ["not found", "Explore"],
        "found_indicators": ["projects", "contributions"],
    },
    {
        "name": "Bitbucket",
        "url": "https://bitbucket.org/{username}/",
        "method": "status",
        "not_found": ["not found"],
        "found_indicators": ["repositories"],
    },
    {
        "name": "StackOverflow",
        "url": "https://stackoverflow.com/users/?tab=accounts&q={username}",
        "method": "content",
        "not_found": ["no users found"],
        "found_indicators": ["user-card"],
    },
    {
        "name": "HackerRank",
        "url": "https://www.hackerrank.com/{username}",
        "method": "content",
        "not_found": ["not found"],
        "found_indicators": ["profile"],
    },
    {
        "name": "LeetCode",
        "url": "https://leetcode.com/{username}",
        "method": "content",
        "not_found": ["does not exist"],
        "found_indicators": ["profile", "problems"],
    },
    {
        "name": "CodeChef",
        "url": "https://www.codechef.com/users/{username}",
        "method": "content",
        "not_found": ["not found"],
        "found_indicators": ["profile"],
    },
    {
        "name": "Codeforces",
        "url": "https://codeforces.com/profile/{username}",
        "method": "content",
        "not_found": ["not found"],
        "found_indicators": ["profile"],
    },
    {
        "name": "Replit",
        "url": "https://replit.com/@{username}",
        "method": "content",
        "not_found": ["not found"],
        "found_indicators": ["profile", "repls"],
    },
    {
        "name": "Glitch",
        "url": "https://glitch.com/@{username}",
        "method": "content",
        "not_found": ["not found"],
        "found_indicators": ["profile"],
    },

    # ── Creative ──
    {
        "name": "DeviantArt",
        "url": "https://www.deviantart.com/{username}",
        "method": "content",
        "not_found": ["does not exist", "not found"],
        "found_indicators": ["gallery", "profile"],
    },
    {
        "name": "ArtStation",
        "url": "https://www.artstation.com/{username}",
        "method": "content",
        "not_found": ["not found"],
        "found_indicators": ["artwork"],
    },
    {
        "name": "Pixiv",
        "url": "https://www.pixiv.net/users/{username}",
        "method": "status",
        "not_found": ["not found"],
        "found_indicators": ["artwork"],
    },
    {
        "name": "500px",
        "url": "https://500px.com/p/{username}",
        "method": "content",
        "not_found": ["not found"],
        "found_indicators": ["photos"],
    },
    {
        "name": "Unsplash",
        "url": "https://unsplash.com/@{username}",
        "method": "content",
        "not_found": ["not found"],
        "found_indicators": ["photos"],
    },
    {
        "name": "Imgur",
        "url": "https://imgur.com/user/{username}",
        "method": "content",
        "not_found": ["not found"],
        "found_indicators": ["posts"],
    },
    {
        "name": "Giphy",
        "url": "https://giphy.com/{username}",
        "method": "content",
        "not_found": ["not found"],
        "found_indicators": ["gifs"],
    },

    # ── Music ──
    {
        "name": "Spotify",
        "url": "https://open.spotify.com/user/{username}",
        "method": "content",
        "not_found": ["not found"],
        "found_indicators": ["playlists", "profile"],
    },
    {
        "name": "SoundCloud",
        "url": "https://soundcloud.com/{username}",
        "method": "content",
        "not_found": ["not found", "We can't find"],
        "found_indicators": ["tracks", "followers"],
    },
    {
        "name": "Bandcamp",
        "url": "https://{username}.bandcamp.com", "method": "status",
        "not_found": ["not found"],
        "found_indicators": ["music", "albums"],
    },
    {
        "name": "Last.fm",
        "url": "https://www.last.fm/user/{username}",
        "method": "content",
        "not_found": ["not found"],
        "found_indicators": ["library", "artists"],
    },
    {
        "name": "YouTube",
        "url": "https://www.youtube.com/@{username}",
        "method": "content",
        "not_found": ["not found", "does not exist"],
        "found_indicators": ["videos", "subscribers"],
    },

    # ── Messaging ──
    {
        "name": "Telegram",
        "url": "https://t.me/{username}",
        "method": "content",
        "not_found": ["not found", "can be found"],
        "found_indicators": ["profile", "tgme"],
    },
    {
        "name": "Slack",
        "url": "https://{username}.slack.com", "method": "status",
        "not_found": ["not found"],
        "found_indicators": ["workspace"],
    },
    {
        "name": "Skype",
        "url": "https://join.skype.com/invite/{username}",
        "method": "status",
        "not_found": ["not found"],
        "found_indicators": ["invite"],
    },

    # ── Forums ──
    {
        "name": "Quora",
        "url": "https://www.quora.com/profile/{username}",
        "method": "content",
        "not_found": ["not found", "Page Not Found"],
        "found_indicators": ["profile", "answers"],
    },
    {
        "name": "Medium",
        "url": "https://medium.com/@{username}",
        "method": "content",
        "not_found": ["not found", "404"],
        "found_indicators": ["articles", "profile"],
    },
    {
        "name": "Hashnode",
        "url": "https://hashnode.com/@{username}",
        "method": "status",
        "not_found": ["not found"],
        "found_indicators": ["profile"],
    },
    {
        "name": "Substack",
        "url": "https://{username}.substack.com", "method": "status",
        "not_found": ["not found"],
        "found_indicators": ["newsletter"],
    },
    {
        "name": "WordPress",
        "url": "https://{username}.wordpress.com", "method": "status",
        "not_found": ["does not exist"],
        "found_indicators": ["blog"],
    },
    {
        "name": "Blogger",
        "url": "https://{username}.blogspot.com", "method": "status",
        "not_found": ["not found"],
        "found_indicators": ["blog"],
    },

    # ── Shopping / Finance ──
    {
        "name": "Etsy",
        "url": "https://www.etsy.com/shop/{username}",
        "method": "content",
        "not_found": ["does not exist", "not found"],
        "found_indicators": ["shop", "listings"],
    },
    {
        "name": "eBay",
        "url": "https://www.ebay.com/usr/{username}",
        "method": "content",
        "not_found": ["not found"],
        "found_indicators": ["feedback", "items"],
    },
    {
        "name": "PayPal",
        "url": "https://www.paypal.me/{username}",
        "method": "content",
        "not_found": ["not found"],
        "found_indicators": ["profile"],
    },
    {
        "name": "Coinbase",
        "url": "https://www.coinbase.com/{username}",
        "method": "status",
        "not_found": ["not found"],
        "found_indicators": ["profile"],
    },
    {
        "name": "Binance",
        "url": "https://www.binance.com/en/users/{username}",
        "method": "status",
        "not_found": ["not found"],
        "found_indicators": ["profile"],
    },

    # ── Other ──
    {
        "name": "Wikipedia",
        "url": "https://en.wikipedia.org/wiki/User:{username}",
        "method": "content",
        "not_found": ["does not exist", "does not have"],
        "found_indicators": ["contributions", "user page"],
    },
    {
        "name": "IMDb",
        "url": "https://www.imdb.com/user/{username}",
        "method": "content",
        "not_found": ["not found"],
        "found_indicators": ["ratings"],
    },
    {
        "name": "Goodreads",
        "url": "https://www.goodreads.com/{username}",
        "method": "content",
        "not_found": ["not found", "page not found"],
        "found_indicators": ["books", "shelves"],
    },
    {
        "name": "MyAnimeList",
        "url": "https://myanimelist.net/profile/{username}",
        "method": "content",
        "not_found": ["not found"],
        "found_indicators": ["anime", "manga"],
    },
    {
        "name": "Letterboxd",
        "url": "https://letterboxd.com/{username}",
        "method": "content",
        "not_found": ["not found"],
        "found_indicators": ["films", "diary"],
    },
    {
        "name": "Strava",
        "url": "https://www.strava.com/athletes/{username}",
        "method": "content",
        "not_found": ["not found"],
        "found_indicators": ["activities"],
    },
    {
        "name": "Duolingo",
        "url": "https://www.duolingo.com/profile/{username}",
        "method": "content",
        "not_found": ["not found"],
        "found_indicators": ["streak", "courses"],
    },
    {
        "name": "Coursera",
        "url": "https://www.coursera.org/user/{username}",
        "method": "content",
        "not_found": ["not found"],
        "found_indicators": ["courses"],
    },
    {
        "name": "Udemy",
        "url": "https://www.udemy.com/user/{username}",
        "method": "content",
        "not_found": ["not found"],
        "found_indicators": ["courses"],
    },
    {
        "name": "Khan Academy",
        "url": "https://www.khanacademy.org/profile/{username}",
        "method": "content",
        "not_found": ["not found"],
        "found_indicators": ["profile"],
    },
    {
        "name": "Fitbit",
        "url": "https://www.fitbit.com/user/{username}",
        "method": "status",
        "not_found": ["not found"],
        "found_indicators": ["profile"],
    },
    {
        "name": "Wattpad",
        "url": "https://www.wattpad.com/user/{username}",
        "method": "content",
        "not_found": ["not found"],
        "found_indicators": ["stories"],
    },
    {
        "name": "Patreon",
        "url": "https://www.patreon.com/{username}",
        "method": "content",
        "not_found": ["not found", "404"],
        "found_indicators": ["creators", "posts"],
    },
    {
        "name": "Gravatar",
        "url": "https://en.gravatar.com/{username}",
        "method": "content",
        "not_found": ["not found", "Profile not found"],
        "found_indicators": ["profile", "avatar"],
    },
    {
        "name": "BuyMeACoffee",
        "url": "https://buymeacoffee.com/{username}",
        "method": "content",
        "not_found": ["not found", "404"],
        "found_indicators": ["profile"],
    },
    {
        "name": "Gravatar2",
        "url": "https://gravatar.com/{username}",
        "method": "status",
        "not_found": ["not found"],
        "found_indicators": ["profile"],
    },
    {
        "name": "Codepen",
        "url": "https://codepen.io/{username}",
        "method": "content",
        "not_found": ["not found"],
        "found_indicators": ["pens", "profile"],
    },
    {
        "name": "Kaggle",
        "url": "https://www.kaggle.com/{username}",
        "method": "content",
        "not_found": ["not found"],
        "found_indicators": ["datasets", "competitions"],
    },
    {
        "name": "TryHackMe",
        "url": "https://tryhackme.com/p/{username}",
        "method": "content",
        "not_found": ["not found"],
        "found_indicators": ["profile"],
    },
    {
        "name": "HackTheBox",
        "url": "https://app.hackthebox.com/users/{username}",
        "method": "status",
        "not_found": ["not found"],
        "found_indicators": ["profile"],
    },
    {
        "name": "Bugcrowd",
        "url": "https://bugcrowd.com/{username}",
        "method": "content",
        "not_found": ["not found"],
        "found_indicators": ["profile"],
    },
    {
        "name": "HackerOne",
        "url": "https://hackerone.com/{username}",
        "method": "content",
        "not_found": ["not found"],
        "found_indicators": ["profile", "reports"],
    },
]


class UsernameOSINT(BaseTool):
    """Wrapper around sherlock for username enumeration across platforms."""

    name = "sherlock"
    binary = "sherlock"
    description = "Username search across 400+ social platforms"

    def scan(self, target: str, **kwargs) -> ToolResult:
        """Search for a username across platforms."""
        username = target.strip().lower()
        # Sanitize username
        username = re.sub(r"[^a-zA-Z0-9._-]", "", username)
        if not username:
            return ToolResult(
                tool=self.name,
                target=target,
                success=False,
                error="Invalid username — must contain alphanumeric characters.",
            )

        if not self.installed:
            logger.info(f"[{self.name}] Binary not found, using Python fallback")
            return self._fallback_scan(username, **kwargs)

        cmd = [
            "sherlock",
            username,
            "--print-found",
            "--timeout", str(kwargs.get("timeout_per_site", 10)),
            "--output", "/dev/stdout",
        ]

        if kwargs.get("sites"):
            for site in kwargs["sites"]:
                cmd.extend(["--site", site])
        if kwargs.get("nsfw"):
            cmd.append("--nsfw")

        start = time.time()
        result = self._run_cmd(cmd, timeout=kwargs.get("timeout", 300))
        duration = time.time() - start

        findings = []
        if result.stdout:
            for line in result.stdout.strip().split("\n"):
                line = line.strip()
                # sherlock output: [+] username: https://site.com/username
                match = re.search(r"\[\+\]\s*(?:\w+):\s*(https?://\S+)", line)
                if match:
                    url = match.group(1)
                    # Extract platform name from URL
                    try:
                        from urllib.parse import urlparse
                        host = urlparse(url).hostname or ""
                        platform = host.replace("www.", "").split(".")[0]
                    except Exception:
                        platform = "unknown"

                    findings.append({
                        "title": f"Username Found: {username}",
                        "severity": "INFO",
                        "description": f"Username '{username}' found on {platform}",
                        "evidence": url,
                        "url": url,
                        "platform": platform,
                        "username": username,
                        "remediation": "Review exposed accounts for sensitive information. Consider privacy settings.",
                    })

        return ToolResult(
            tool=self.name,
            target=username,
            success=result.returncode == 0,
            findings=findings,
            raw_output=result.stdout,
            error=result.stderr if result.returncode != 0 else "",
            duration=duration,
        )

    def _fallback_scan(self, username: str, **kwargs) -> ToolResult:
        """Fallback: HTTP-based username check on 20+ popular platforms."""
        try:
            import httpx
        except ImportError:
            return ToolResult(
                tool=f"{self.name}(fallback)",
                target=username,
                success=False,
                error="httpx not installed. Run: pip install httpx",
            )

        findings: List[Dict[str, Any]] = []
        start = time.time()
        limiter = get_limiter(rps=5.0)

        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        client = httpx.Client(
            follow_redirects=True,
            timeout=10,
            verify=False,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
            },
        )

        def check_platform(platform: Dict[str, Any]) -> Optional[Dict[str, Any]]:
            """Check a single platform for the username."""
            url = platform["url"].format(username=username)
            method = platform["method"]
            not_found_indicators = platform.get("not_found", [])
            found_indicators = platform.get("found_indicators", [])
            name = platform["name"]

            try:
                resp = client.get(url)
                body = resp.text
                body_lower = body.lower()
                status = resp.status_code

                # ── Detection logic ──
                found = False

                if method == "status":
                    # Status-code based detection
                    if status == 200:
                        # Verify it's not a soft 404
                        if not any(ind.lower() in body_lower for ind in not_found_indicators):
                            found = True
                    elif status == 404:
                        found = False
                    else:
                        # Some sites return 302/301 for valid profiles
                        if status in (301, 302) and not any(ind.lower() in body_lower for ind in not_found_indicators):
                            found = True

                elif method == "content":
                    # Content-based detection
                    if status == 200:
                        has_not_found = any(ind.lower() in body_lower for ind in not_found_indicators)
                        has_found = any(ind.lower() in body_lower for ind in found_indicators) if found_indicators else True

                        if not has_not_found and has_found:
                            found = True

                if found:
                    return {
                        "title": f"Username Found: {username}",
                        "severity": "INFO",
                        "description": f"Username '{username}' found on {name}",
                        "evidence": url,
                        "url": url,
                        "platform": name,
                        "username": username,
                        "status_code": status,
                        "remediation": "Review exposed accounts for sensitive information. Consider privacy settings.",
                    }
                return None

            except (httpx.ConnectError, httpx.TimeoutException):
                return None
            except Exception as e:
                logger.debug(f"[{self.name}] Error checking {name}: {e}")
                return None

        # Check platforms concurrently
        max_workers = min(10, len(FALLBACK_PLATFORMS))
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {
                pool.submit(check_platform, platform): platform["name"]
                for platform in FALLBACK_PLATFORMS
            }
            for future in as_completed(futures):
                result = future.result()
                if result:
                    findings.append(result)

        client.close()
        duration = time.time() - start

        # Sort findings by platform name
        findings.sort(key=lambda f: f.get("platform", ""))

        logger.info(
            f"[{self.name}(fallback)] Checked {len(FALLBACK_PLATFORMS)} platforms "
            f"for '{username}': {len(findings)} found in {duration:.1f}s"
        )

        return ToolResult(
            tool=f"{self.name}(fallback)",
            target=username,
            success=True,
            findings=findings,
            duration=duration,
        )
