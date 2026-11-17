from __future__ import annotations
from .base import SiteModule, registry


class GenericUsernameSite(SiteModule):
    supported = {"username"}

    def __init__(self, name: str, url: str, category: str = "medium",
                 negative_marker: str | None = None):
        self.name = name
        self.category = category
        self.url = url
        self.negative_marker = negative_marker

    async def check(self, client, query: str) -> dict:
        url = self.url.format(u=query)
        try:
            r = await client.get(url)
        except Exception as e:
            return {"status": "error", "url": url, "confidence": 0.0,
                    "evidence": {"error": str(e)}}
        if r.status_code == 200:
            if self.negative_marker and self.negative_marker.lower() in r.text.lower():
                return {"status": "not_found", "url": url, "http_status": 200,
                        "confidence": 0.7, "evidence": {}}
            return {"status": "found", "url": url, "http_status": 200,
                    "confidence": 0.85, "evidence": {}}
        if r.status_code == 404:
            return {"status": "not_found", "url": url, "http_status": 404,
                    "confidence": 0.9, "evidence": {}}
        return {"status": "inconclusive", "url": url,
                "http_status": r.status_code, "confidence": 0.3, "evidence": {}}


BUILTIN = [
    ("GitHub",       "https://github.com/{u}",                   "major"),
    ("Reddit",       "https://www.reddit.com/user/{u}",          "major"),
    ("GitLab",       "https://gitlab.com/{u}",                   "major"),
    ("Keybase",      "https://keybase.io/{u}",                   "major"),
    ("HackerNews",   "https://news.ycombinator.com/user?id={u}", "major"),
    ("Medium",       "https://medium.com/@{u}",                  "medium"),
    ("Pinterest",    "https://www.pinterest.com/{u}/",           "medium"),
    ("Twitch",       "https://www.twitch.tv/{u}",                "medium"),
    ("Steam",        "https://steamcommunity.com/id/{u}",        "medium"),
    ("Behance",      "https://www.behance.net/{u}",              "medium"),
    ("Dribbble",     "https://dribbble.com/{u}",                 "medium"),
    ("SoundCloud",   "https://soundcloud.com/{u}",               "medium"),
    ("Vimeo",        "https://vimeo.com/{u}",                    "medium"),
    ("About.me",     "https://about.me/{u}",                     "medium"),
    ("Telegram",     "https://t.me/{u}",                         "medium"),
    ("Dev.to",       "https://dev.to/{u}",                       "medium"),
    ("HackerOne",    "https://hackerone.com/{u}",                "major"),
    ("ProductHunt",  "https://www.producthunt.com/@{u}",         "medium"),
    ("CodePen",      "https://codepen.io/{u}",                   "medium"),
    ("Figma",        "https://www.figma.com/@{u}",               "medium"),
    ("Kaggle",       "https://www.kaggle.com/{u}",               "medium"),
    ("Replit",       "https://replit.com/@{u}",                  "medium"),
    ("Mastodon",     "https://mastodon.social/@{u}",             "medium"),
    ("Bluesky",      "https://bsky.app/profile/{u}.bsky.social", "medium"),
]


def load_builtin():
    for name, tmpl, cat in BUILTIN:
        registry.register(GenericUsernameSite(name, tmpl, cat))
