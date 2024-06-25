import re


def escape_markdown(text):
    replacements = [
        ("_", r"\_"),
        ("*", r"\*"),
        ("[", r"\["),
        ("]", r"\]"),
        ("(", r"\("),
        (")", r"\)"),
        ("~", r"\~"),
        # ("`", r"\`"),
        (">", r"\>"),
        ("#", r"\#"),
        ("+", r"\+"),
        ("-", r"\-"),
        ("=", r"\="),
        ("|", r"\|"),
        ("{", r"\{"),
        ("}", r"\}"),
        (".", r"\."),
        ("!", r"\!"),
    ]

    for old, new in replacements:
        text = text.replace(old, new)

    return text


def is_url(string):
    pattern = re.compile(
        r"^(https?:\/\/)"  # Protocol
        r"([a-zA-Z0-9_-]+\.)*"  # Subdomain (optional)
        r"([a-zA-Z0-9-]{2,})"  # Domain
        r"(\.[a-zA-Z0-9-]{2,})*"  # Domain extension
        r"(\.[a-z]{2,6})"  # Top-level domain
        r"([\/\w .-]*)*"  # Path (optional)
        r"(\?[;&a-zA-Z0-9%_.~+=-]*)?"  # Query string (optional)
        r"(#[-a-zA-Z0-9_]*)?$"  # Fragment (optional)
    )
    return re.match(pattern, string) is not None


def telegram_markdown_formatter(text: str, **kwargs):
    if kwargs.get("bot", "telegram") != "telegram":
        return text
    parts = text.split("`")
    for i, p in enumerate(parts):
        if i % 2 == 0:
            parts[i] = escape_markdown(p)
    return "`".join(parts)


# Define a regular expression pattern for a URL
url_pattern = re.compile(
    r"^(https?|ftp):\/\/"  # http:// or https:// or ftp://
    r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|"  # domain...
    r"localhost|"  # localhost...
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|"  # ...or ipv4
    r"\[?[A-F0-9]*:[A-F0-9:]+\]?)"  # ...or ipv6
    r"(?::\d+)?"  # optional port
    r"(?:\/[^\s]*)?$",  # resource path
    re.IGNORECASE,
)


def is_valid_url(url: str) -> bool:
    return re.match(url_pattern, url) is not None


def split_text(text, max_chunk_size=4096):
    # Split text into paragraphs
    paragraphs = text.split("\n")
    chunks = []
    current_chunk = ""

    for paragraph in paragraphs:
        if len(current_chunk) + len(paragraph) + 1 > max_chunk_size:
            if current_chunk:
                chunks.append(current_chunk.strip())
                current_chunk = ""
        if len(paragraph) > max_chunk_size:
            # Split paragraph into sentences
            sentences = re.split(r"(?<=[.!?]) +", paragraph)
            for sentence in sentences:
                if len(current_chunk) + len(sentence) + 1 > max_chunk_size:
                    if current_chunk:
                        chunks.append(current_chunk.strip())
                        current_chunk = ""
                if len(sentence) > max_chunk_size:
                    # Split sentence into words
                    words = sentence.split(" ")
                    for word in words:
                        if len(current_chunk) + len(word) + 1 > max_chunk_size:
                            if current_chunk:
                                chunks.append(current_chunk.strip())
                                current_chunk = ""
                        current_chunk += word + " "
                else:
                    current_chunk += sentence + " "
        else:
            current_chunk += paragraph + "\n"
    if current_chunk:
        chunks.append(current_chunk.strip())

    return chunks
