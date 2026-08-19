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


def test_extract_telegram_handles_decodes_html_entities_inside_supported_uri() -> None:
    raw = (
        "trojan://password@example.org:443?security=tls&sni=www.example.org"
        "#channel-%26commat%3BEntity_Channel"
    )

    assert extract_telegram_handles(raw) == {"entity_channel"}


def test_extract_profile_uris_reads_supported_uri_from_data_url_attribute() -> None:
    html = """
    <div class="tgme_widget_message" data-post="channel_name/21">
      <div class="tgme_widget_message_text">
        <span data-url="hysteria2://password@example.org:443?security=tls&sni=www.example.org">
          profile
        </span>
      </div>
      <time datetime="2026-08-15T11:00:00+00:00"></time>
    </div>
    """

    posts = parse_preview_posts(html, "channel_name", NOW, 24)

    assert extract_profile_uris(posts) == [
        "hysteria2://password@example.org:443?security=tls&sni=www.example.org"
    ]


def test_extract_profile_uris_decodes_percent_encoded_attribute_value() -> None:
    html = """
    <div class="tgme_widget_message" data-post="channel_name/22">
      <div class="tgme_widget_message_text">
        <a
          href="trojan%3A%2F%2Fpassword%40example.org%3A443%3Fsecurity%3Dtls%26sni%3Dwww.example.org"
        >
          profile
        </a>
      </div>
      <time datetime="2026-08-15T11:30:00+00:00"></time>
    </div>
    """

    posts = parse_preview_posts(html, "channel_name", NOW, 24)

    assert extract_profile_uris(posts) == [
        "trojan://password@example.org:443?security=tls&sni=www.example.org"
    ]


def test_extract_profile_uris_reads_supported_uri_from_strict_base64_container() -> None:
    html = """
    <div class="tgme_widget_message" data-post="channel_name/23">
      <div class="tgme_widget_message_text">
        aHkyOi8vcGFzc3dvcmRAZXhhbXBsZS5vcmc6NDQzP3NlY3VyaXR5PXRscyZzbmk9d3d3LmV4YW1wbGUub3Jn
      </div>
      <time datetime="2026-08-15T11:45:00+00:00"></time>
    </div>
    """

    posts = parse_preview_posts(html, "channel_name", NOW, 24)

    assert extract_profile_uris(posts) == [
        "hy2://password@example.org:443?security=tls&sni=www.example.org"
    ]


def test_parse_preview_posts_uses_known_iso_date_attribute_fallbacks() -> None:
    html = """
    <div
      class="tgme_widget_message"
      data-post="channel_name/24"
      data-datetime="2026-08-15T11:00:00Z"
    >
      <div class="tgme_widget_message_text">vless://from-data-datetime</div>
    </div>
    <div class="tgme_widget_message" data-post="channel_name/25">
      <a class="tgme_widget_message_date" title="2026-08-15T10:00:00+00:00">date</a>
      <div class="tgme_widget_message_text">trojan://from-title</div>
    </div>
    """

    posts = parse_preview_posts(html, "channel_name", NOW, 24)

    assert [post.message_id for post in posts] == ["24", "25"]


def test_parse_preview_posts_uses_unix_timestamp_date_fallback() -> None:
    html = """
    <div class="tgme_widget_message" data-post="channel_name/26" data-timestamp="1786791600">
      <div class="tgme_widget_message_text">hy2://from-timestamp</div>
    </div>
    """

    posts = parse_preview_posts(html, "channel_name", NOW, 24)

    assert [post.message_id for post in posts] == ["26"]
