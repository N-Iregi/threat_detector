from api_client_details import threatfox_post

# function to search a specific IOC by its id
def search_ioc_by_id():
    ioc_id = input("Enter IOC ID to search for specific IOC: ").strip()
    if not ioc_id.isdigit():
        print("‼ You have entered an invalid ID. Please enter a valid numeric ID.")
        return

    query_params = {"query": "ioc", "id": ioc_id}
    res = threatfox_post(query_params)

    if not res:
        return

    # Basic check to ensure ioc_data has content
    if "ioc" not in res or "threat_type" not in res:
        print("\n===========================================")
        print("❌ API RESPONSE ERROR: Could not fetch valid IOC data.")
        print("===========================================\n")
        return

    print(f"\n🎯 IOC found by id entered:")	

    print(f"IOC: {res.get('ioc')} | Type: {res.get('ioc_type')} | Tags: {res.get('tags')}")
    print(f"Threat type of IOC: {res['threat_type']} - {res['threat_type_desc']}")
    print(f"Malware name in IOC: {res['malware_printable']}")
    print(f"Level of malice carried: {res['confidence_level']}\n")

    samples = res.get("malware_samples", [])
    if samples:
        print("\n🧫 Malware Samples:")
        for sample in samples:
            print(f" - Time: {sample['time_stamp']}")
            print(f"   MD5: {sample['md5_hash']}")
            print(f"   SHA256: {sample['sha256_hash']}")
            print(f"   Bazaar Link: {sample['malware_bazaar']}\n")
