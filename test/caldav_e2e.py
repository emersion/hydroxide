#!/usr/bin/env python3
"""End-to-end test for hydroxide CalDAV support (PR #282 + fixes).

Exercises the full lifecycle against a running `hydroxide caldav`/`serve`
instance and a live ProtonMail account that has at least one calendar:

  discover -> create -> read (PROPFIND + GET) -> time-range query -> update -> delete

Usage:
  export HYDROXIDE_CALDAV_URL=http://127.0.0.1:8081
  export HYDROXIDE_USER=you@proton.me
  export HYDROXIDE_BRIDGE_PASS=<bridge password from `hydroxide auth`>
  python3 test/caldav_e2e.py

Exits non-zero if any check fails. Requires `requests` (pip install requests).
"""
import os
import re
import sys
import uuid

import requests
from requests.auth import HTTPBasicAuth

BASE = os.environ.get("HYDROXIDE_CALDAV_URL", "http://127.0.0.1:8081").rstrip("/")
USER = os.environ["HYDROXIDE_USER"]
PASS = os.environ["HYDROXIDE_BRIDGE_PASS"]
AUTH = HTTPBasicAuth(USER, PASS)

PASSED, FAILED = [], []


def check(cond, label):
    (PASSED if cond else FAILED).append(label)
    print(("  PASS " if cond else "  FAIL ") + label)


def req(method, path, body=None, headers=None, ctype=None):
    h = dict(headers or {})
    if ctype:
        h["Content-Type"] = ctype
    return requests.request(method, BASE + path, auth=AUTH, headers=h, data=body, timeout=40)


def discover_calendar():
    body = ('<d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">'
            "<d:prop><d:resourcetype/><d:displayname/></d:prop></d:propfind>")
    resp = req("PROPFIND", "/caldav/calendars/", body, {"Depth": "1"}, "application/xml")
    for chunk in re.findall(r"<response[^>]*>.*?</response>", resp.text, re.S):
        href = re.search(r"<href>([^<]+)</href>", chunk).group(1)
        if "<calendar" in chunk and href.rstrip("/") != "/caldav/calendars":
            return href.rstrip("/")
    raise SystemExit("no calendar found - create one at calendar.proton.me first")


def listobjs(cal):
    body = ('<d:propfind xmlns:d="DAV:"><d:prop><d:getetag/>'
            '<c:calendar-data xmlns:c="urn:ietf:params:xml:ns:caldav"/></d:prop></d:propfind>')
    resp = req("PROPFIND", cal, body, {"Depth": "1"}, "application/xml")
    hrefs = re.findall(r"<(?:[a-z]+:)?href>([^<]+\.ics)</(?:[a-z]+:)?href>", resp.text)
    return resp.status_code, hrefs, resp.text


def query_time_range(cal, start, end):
    body = (f'<c:calendar-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">'
            f"<d:prop><d:getetag/><c:calendar-data/></d:prop>"
            f'<c:filter><c:comp-filter name="VCALENDAR"><c:comp-filter name="VEVENT">'
            f'<c:time-range start="{start}" end="{end}"/>'
            f"</c:comp-filter></c:comp-filter></c:filter></c:calendar-query>")
    resp = req("REPORT", cal, body, {"Depth": "1"}, "application/xml")
    return resp.status_code, [u.strip() for u in re.findall(r"UID:([^\r\n&]+)", resp.text)]


def cleanup(cal):
    for h in listobjs(cal)[1]:
        et = req("GET", h).headers.get("ETag")
        req("DELETE", h, None, {"If-Match": et} if et else {})


def main():
    cal = discover_calendar()
    print("calendar:", cal)
    cleanup(cal)

    uid = "hydroxide-e2e-" + uuid.uuid4().hex[:10]
    ics = ("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//hydroxide-e2e//EN\r\n"
           f"BEGIN:VEVENT\r\nUID:{uid}\r\nDTSTAMP:20260604T120000Z\r\n"
           "DTSTART:20260610T150000Z\r\nDTEND:20260610T160000Z\r\n"
           "SUMMARY:Hydroxide CalDAV test event\r\nDESCRIPTION:created by e2e\r\n"
           "LOCATION:Test Lab\r\nSEQUENCE:0\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n")

    print("== CREATE ==")
    check(req("PUT", cal + "/" + uid + ".ics", ics, {"If-None-Match": "*"},
              "text/calendar").status_code in (201, 204), "CREATE returns 201/204")

    print("== READ (PROPFIND Depth:1) ==")
    sc, hrefs, body = listobjs(cal)
    check(sc == 207, "PROPFIND returns 207")
    check("Hydroxide CalDAV test event" in body, "SUMMARY round-trips")
    check("Test Lab" in body, "LOCATION round-trips")
    href = next(h for h in hrefs if uid in req("GET", h).text)

    print("== GET (single object) ==")
    g = req("GET", href)
    check(g.status_code == 200 and uid in g.text, "GET returns event with our UID")

    print("== TIME-RANGE QUERY ==")
    sc, uids = query_time_range(cal, "20260101T000000Z", "20270101T000000Z")
    check(uid in uids, "event IN range is returned")
    sc, uids = query_time_range(cal, "20250101T000000Z", "20250201T000000Z")
    check(uid not in uids, "event OUT of range is excluded")

    print("== UPDATE (bump SEQUENCE) ==")
    et = g.headers.get("ETag")
    ics_u = (ics.replace("test event", "test event [UPDATED]")
                .replace("SEQUENCE:0", "SEQUENCE:1")
                .replace("Test Lab", "Updated Room"))
    check(req("PUT", href, ics_u, {"If-Match": et} if et else {},
              "text/calendar").status_code in (200, 201, 204), "UPDATE returns 2xx")
    sc, hrefs, body = listobjs(cal)
    check("[UPDATED]" in body, "updated SUMMARY reflected")
    check("Updated Room" in body, "updated LOCATION reflected")

    print("== DELETE ==")
    href2 = next(h for h in hrefs if "[UPDATED]" in req("GET", h).text)
    de = req("GET", href2).headers.get("ETag")
    check(req("DELETE", href2, None, {"If-Match": de} if de else {}).status_code in (200, 204),
          "DELETE returns 200/204")
    check("[UPDATED]" not in listobjs(cal)[2], "event gone after delete")

    print(f"\n{len(PASSED)}/{len(PASSED) + len(FAILED)} passed")
    if FAILED:
        for f in FAILED:
            print("  FAILED:", f)
        sys.exit(1)
    print("ALL PASS")


if __name__ == "__main__":
    main()
