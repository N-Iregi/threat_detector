from api_client_details import threatfox_post
from regex_validation import valid_domain, valid_ip, valid_url, hash_validity

def submit_ioc():
    print("** Submit an IOC to Threatfox **")
    print("** Help us lead the charge in threat intelligence and incident response 🛡 ⚔  **")

    ioc_type = input("IOC type (e.g., url, domain): ").strip()
    threat_type = input("Threat type (e.g., payload_delivery, botnet_cc): ").strip()
    malware = input("Enter Malpedia malware name(Reference 'Get malware list' option to look up supported malware families): ").strip()
    confidence = input("Confidence level (0-100): ").strip()
    iocs = input("Enter IOC you want to submit(e.g tooeviltoexist.com): ").strip()
    comment = input("Comment on the IOC you want to submit(optional): ")

    missing = []
    if not ioc_type:
        missing.append("IOC Type")
    if not iocs:
        missing.append("iocs")
    if not threat_type:
        missing.append("Threat Type")
    if not malware:
        missing.append("Malware family name")
    if not confidence:
        missing.append("Confidence Level")

    if missing:
        print(f"\n[ERROR] The following fields are required: {', '.join(missing)}")
        return

    try:
        confidence = int(confidence)
        if not (0 <= confidence <= 100):
            raise ValueError
    except ValueError:
        print("ERROR❗❗: Confidence must be an integer between 0 and 100.")
        return

    # Validate IOC based on its type
    ioc_valid = False
    if ioc_type == "domain":
        ioc_valid = valid_domain(iocs)
    elif ioc_type == "ip":
        ioc_valid = valid_ip(iocs)
    elif ioc_type == "url":
        ioc_valid = valid_url(iocs)
    elif ioc_type in ["md5", "sha1", "sha256"]:
        ioc_valid = valid_hash(ioc_type, iocs)

    if not ioc_valid:
        print(f"❌ ERROR: The IOC value '{ioc}' is not valid for type '{ioc_type}'. Please check and try again.")
        return


    query_params = {
        "query":            "submit_ioc",
        "threat_type":      threat_type,
        "ioc_type":         ioc_type,
        "malware":          malware,
		"iocs":             [iocs],
        "confidence_level": confidence,
        "comment":          comment,
    }

    submit_response = threatfox_post(query_params)

    if submit_response:
        print("\n🎉 HOORAY!! Your submission is successful! Thank you for contributing to a safer cyber space")
    else:
        print("\n😞 HMMM... Unfortunately your submission failed. Please try again later.")
