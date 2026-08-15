from datetime import UTC, datetime

from subscription_collector.telegram import (
    extract_profile_uris,
    extract_telegram_handles,
    parse_preview_posts,
)

NOW = datetime(2026, 8, 15, 12, 0, tzinfo=UTC)

PREVIEW_HTML = """
<div class="tgme_widget_message" data-post="channel_name/20">
  <div class="tgme_widget_message_text">
    vless://recent-text <a href="trojan://recent-href">recent link</a>
  </div>
  <time datetime="2026-08-14T12:00:00+00:00"></time>
</div>
<div class="tgme_widget_message" data-post="channel_name/19">
  <div class="tgme_widget_message_text">hy2://old-profile</div>
  <time datetime="2026-08-10T12:00:00+00:00"></time>
</div>
<div class="tgme_widget_message" data-post="channel_name/18">
  <div class="tgme_widget_message_text">hysteria2://missing-date</div>
</div>
<div class="tgme_widget_message" data-post="channel_name/17">
  <div class="tgme_widget_message_text">ss://unsupported</div>
  <time datetime="2026-08-15T10:00:00+00:00"></time>
</div>
"""


def test_extract_telegram_handles_accepts_only_explicit_public_forms() -> None:
    raw = (
        "@One_Name https://t.me/Two_Name https://t.me/s/Three_Name "
        "https://telegram.me/Four_Name tg://resolve?domain=Five_Name "
        "%40Six_Name https://t.me/+private https://t.me/joinchat/private bare_name"
    )

    assert extract_telegram_handles(raw) == {
        "one_name",
        "two_name",
        "three_name",
        "four_name",
        "five_name",
        "six_name",
    }


def test_parse_preview_keeps_only_dated_recent_posts_and_hrefs() -> None:
    posts = parse_preview_posts(PREVIEW_HTML, "channel_name", NOW, 72)

    assert [post.message_id for post in posts] == ["20", "17"]
    assert posts[0].hrefs == ("trojan://recent-href",)
    assert posts[0].text == "vless://recent-text recent link"


def test_extract_profile_uris_supports_only_project_protocols() -> None:
    posts = parse_preview_posts(PREVIEW_HTML, "channel_name", NOW, 72)

    assert extract_profile_uris(posts) == ["vless://recent-text", "trojan://recent-href"]
