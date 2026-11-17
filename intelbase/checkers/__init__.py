"""Checkers package exporting all available OSINT site checkers."""
from .base import BaseChecker, CheckResult
from .check_github import GitHubChecker
from .check_twitter import TwitterChecker
from .check_reddit import RedditChecker
from .check_spotify import SpotifyChecker
from .check_discord import DiscordChecker

ALL_CHECKERS = [
    GitHubChecker(),
    TwitterChecker(),
    RedditChecker(),
    SpotifyChecker(),
    DiscordChecker(),
]
