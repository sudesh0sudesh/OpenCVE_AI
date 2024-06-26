import pytest

from opencve.commands.utils import CveUtil
from opencve.extensions import db
from opencve.models import vendors
from opencve.models.alerts import Alert
from opencve.models.cve import Cve
from opencve.models.events import Event
from opencve.models.products import Product
from opencve.models.users import User
from opencve.models.vendors import Vendor
from opencve.tasks.alerts import filter_events, handle_alerts


@pytest.mark.parametrize(
    "types",
    [
        (["cvss"]),
        (["cvss", "summary"]),
        (["cvss", "summary", "references"]),
        (["cvss", "summary", "references", "cpes"]),
        (["cvss", "summary", "references", "cpes", "cwes"]),
    ],
)
def test_filter_events(app, create_user, create_cve, open_file, types):
    def create_events(cve):
        for t in ["summary", "cpes", "cwes", "cvss", "references"]:
            CveUtil.create_event(
                cve, open_file(f"modified_cves/CVE-2018-18074_{t}.json"), t, {}
            )

    user = create_user()
    cve = create_cve("CVE-2018-18074")
    create_events(cve)

    events = Event.query.all()
    assert sorted([e.type.code for e in events]) == sorted(
        ["summary", "cpes", "cwes", "cvss", "references"]
    )

    assert sorted([e.type.code for e in filter_events(user, events)]) == sorted(
        ["summary", "cpes", "cwes", "cvss", "references"]
    )

    # Return events based on user's filters
    user.filters_notifications = {"cvss": 0, "event_types": types}
    db.session.commit()
    assert sorted([e.type.code for e in filter_events(user, events)]) == sorted(types)


def test_filter_events_first_time(create_user, create_cve, create_vendor, open_file):
    cve = create_cve("CVE-2018-18074")
    event = CveUtil.create_event(
        cve,
        open_file(f"modified_cves/CVE-2018-18074_first_time_1.json"),
        "first_time",
        ["opencveio", "opencveio$PRODUCT$opencveio"],
    )

    # User1 doesn't have the first_time type
    user1 = create_user("user1")
    user1.filters_notifications = {"cvss": 0, "event_types": ["summary"]}
    db.session.commit()
    assert filter_events(user1, [event]) == []

    # User2 hasn't subscribed to opencve vendor
    user2 = create_user("user2")
    vendor = create_vendor("not_existing")
    user2.vendors.append(vendor)
    db.session.commit()
    assert filter_events(user2, [event]) == []

    # User3 has subscribed to opencve vendor
    user3 = create_user("user3")
    vendor = create_vendor("opencveio")
    user3.vendors.append(vendor)
    db.session.commit()
    assert filter_events(user3, [event]) == [event]


def test_no_alerts(create_cve):
    handle_alerts()
    assert Alert.query.count() == 0

    # Create a CVE without events
    create_cve("CVE-2018-18074")
    assert Alert.query.count() == 0


def test_handle_alerts_no_subscription(create_cve, handle_events):
    # Create a new CVE with a 'new_cve' event
    handle_events("modified_cves/CVE-2018-18074.json")
    event = Event.query.first()
    assert event.type == "new_cve"
    assert event.review == False

    handle_alerts()

    assert event.review == True
    assert Alert.query.count() == 0


def test_alert_vendor_subscription(create_cve, create_user, handle_events):
    handle_events("modified_cves/CVE-2018-18074.json")
    cve = Cve.query.first()
    event = Event.query.first()
    assert event.type == "new_cve"
    assert event.review == False

    # Create a user with a vendor subscription
    user = create_user()
    vendor = Vendor.query.filter_by(name="canonical").first()
    user.vendors.append(vendor)
    db.session.commit()

    handle_alerts()
    assert event.review == True

    # An alert has been created
    alerts = Alert.query.all()
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.user.id == user.id
    assert len(alert.events) == 1
    assert alert.events[0].id == event.id
    assert alert.cve.id == cve.id
    assert alert.notify == False
    assert alert.details == {
        "filters": ["new_cve"],
        "products": [],
        "vendors": ["canonical"],
    }


def test_alert_product_subscription(create_cve, create_user, handle_events):
    handle_events("modified_cves/CVE-2018-18074.json")
    cve = Cve.query.first()
    event = Event.query.first()
    assert event.type == "new_cve"
    assert event.review == False

    # Create a user with a product subscription
    user = create_user()
    product = Product.query.filter_by(name="ubuntu_linux").first()
    user.products.append(product)
    db.session.commit()

    handle_alerts()
    assert event.review == True

    # An alert has been created
    alerts = Alert.query.all()
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.user.id == user.id
    assert len(alert.events) == 1
    assert alert.events[0].id == event.id
    assert alert.cve.id == cve.id
    assert alert.notify == False
    assert alert.details == {
        "filters": ["new_cve"],
        "products": ["ubuntu_linux"],
        "vendors": [],
    }


def test_alert_cvss_filter(create_cve, create_user, handle_events):
    handle_events("modified_cves/CVE-2018-18074.json")

    # Set the CVSS score to 5.0
    cve = Cve.query.first()
    cve.cvss3 = 5.0
    db.session.commit()

    event = Event.query.first()
    assert event.type == "new_cve"
    assert event.review == False

    # User1 will be alerted (5 > 1)
    vendor = Vendor.query.filter_by(name="canonical").first()
    user1 = create_user("user1")
    user1.vendors.append(vendor)
    user1.filters_notifications = {"cvss": 1.0, "event_types": ["new_cve"]}

    # User2 will not be alerted (5 < 6)
    user2 = create_user("user2")
    user2.vendors.append(vendor)
    user2.filters_notifications = {"cvss": 6.0, "event_types": ["new_cve"]}
    db.session.commit()

    handle_alerts()
    assert event.review == True

    # Only 1 alert has been created for user1
    alerts = Alert.query.all()
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.user.id == user1.id
    assert alert.notify == False
    assert alert.details == {
        "filters": ["new_cve"],
        "products": [],
        "vendors": ["canonical"],
    }


def test_alert_first_time_filter(create_cve, create_user, create_vendor, handle_events):
    create_cve("CVE-2018-18074")
    handle_events("modified_cves/CVE-2018-18074_first_time_1.json")

    # User1 has subscribed to opencve vendor
    user1 = create_user("user1")
    vendor = Vendor.query.filter_by(name="opencveio").first()
    user1.vendors.append(vendor)
    db.session.commit()

    # User2 hasn't subscribed to opencve vendor
    user2 = create_user("user2")
    vendor = create_vendor("another_vendor")
    user2.vendors.append(vendor)
    db.session.commit()

    handle_alerts()

    # There is only 1 alert for user1
    alert_1 = Alert.query.first()
    assert alert_1.user == user1
    assert sorted([e.type.code for e in alert_1.events]) == ["cpes", "first_time"]
    assert sorted(Event.query.filter_by(type="first_time").first().details) == [
        "opencveio",
        "opencveio$PRODUCT$opencve",
    ]

    # We trigger another version of this CVE, but there is no new
    # vendor/product, only a new version of an existing product
    handle_events("modified_cves/CVE-2018-18074_first_time_2.json")
    handle_alerts()

    # The new alert only contains the `cpes` event
    alerts = Alert.query.all()
    alerts.remove(alert_1)
    assert sorted([e.type.code for e in alerts[0].events]) == ["cpes"]


def test_alert_types_empty_filter(create_cve, create_user, handle_events):
    create_cve("CVE-2018-18074")
    vendor = Vendor.query.filter_by(name="canonical").first()

    handle_events("modified_cves/CVE-2018-18074_summary.json")
    event = Event.query.first()
    assert event.type == "summary"

    # The user doesn't want to be alerted for 'summary' events
    user = create_user("user1")
    user.vendors.append(vendor)
    user.filters_notifications = {"cvss": 1.0, "event_types": []}

    handle_alerts()
    assert event.review == True

    # No alert created
    alerts = Alert.query.all()
    assert len(alerts) == 0


def test_alert_types_filter(create_cve, create_user, handle_events):
    create_cve("CVE-2018-18074")
    vendor = Vendor.query.filter_by(name="canonical").first()

    handle_events("modified_cves/CVE-2018-18074_summary.json")
    event = Event.query.first()
    assert event.type == "summary"

    # User1 will be alerted (notification enabled for 'summary')
    vendor = Vendor.query.filter_by(name="canonical").first()
    user1 = create_user("user1")
    user1.vendors.append(vendor)
    user1.filters_notifications = {
        "cvss": 5.0,
        "event_types": ["new_cve", "references", "summary"],
    }

    # User2 will not be alerted (notification disabled for 'summary')
    user2 = create_user("user2")
    user2.vendors.append(vendor)
    user2.filters_notifications = {
        "cvss": 5.0,
        "event_types": ["new_cve", "cwes", "references"],
    }
    db.session.commit()

    handle_alerts()
    assert event.review == True

    # 1 alert created for user1
    alerts = Alert.query.all()
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.user.id == user1.id
    assert alert.notify == False
    assert alert.details == {
        "filters": ["summary"],
        "products": [],
        "vendors": ["canonical"],
    }
