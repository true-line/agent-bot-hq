"""Check the HQ app's signed entitlements against its approved release inputs."""
import plistlib
import re
import sys
from xml.parsers.expat import ExpatError


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: verify-entitlements.py APPROVED_TEAM_ID APPROVED_APP_ID < signed-entitlements.plist")
    team, app = sys.argv[1:]
    if not re.fullmatch(r"[A-Z0-9]{10}", team) or not re.fullmatch(r"[A-Z0-9]{10}\.ai\.true-line\.hq\.signer", app):
        sys.exit("expected an approved team ID and a fully qualified HQ signer App ID")

    try:
        entitlements = plistlib.loads(sys.stdin.buffer.read())
    except (ValueError, plistlib.InvalidFileException, ExpatError):
        sys.exit("invalid signed entitlement plist")
    if not isinstance(entitlements, dict):
        sys.exit("expected a signed entitlement dictionary")
    if entitlements.get("com.apple.developer.team-identifier") != team:
        sys.exit("signed team identifier differs from the approved team")
    if entitlements.get("com.apple.application-identifier") != app:
        sys.exit("signed application identifier differs from the approved HQ App ID")
    if entitlements.get("keychain-access-groups") != [app]:
        sys.exit("expected the approved HQ App ID as the sole signed Keychain group")
    print("HQ signer entitlements match the approved identifiers.")


if __name__ == "__main__":
    main()
