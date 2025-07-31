from api_client_details import threatfox_post
from regex_validation import hash_validity

# function to search for IOCs associated with a certain file hash (MD5 hash or SHA256 hash)
def search_by_file_hash():
    file_hash = input("Enter file hash (MD5/SHA1/SHA256): ").strip()

    if not file_hash or not hash_validity(file_hash):
        print("\n==============================")
        print("❗❗: Please enter a valid file hash to search")
        print("================================\n")
        return

    query_params = {"query": "search_hash", "hash": file_hash}
    res = threatfox_post(query_params)

    ioc_hash_data = res.get("data", [])
    if not isinstance(ioc_hash_data, list) or not all(isinstance(ioc, dict) for ioc in ioc_hash_data):
        print(f"🤔🔎: Unfortunately no IOCs were found for hash: {file_hash}")
        return

    print(f"\n🧐 There are {len(ioc_hash_data)} IOCs found for hash: {file_hash}")
    print("Take a look at their details listed below:\n")

    for index, ioc in enumerate(ioc_hash_data, start=1):
        print(f"💣 Match #{index}")
        print(f"   - IOC ID:            {ioc.get('id')}")
        print(f"   - IOC Value:         {ioc.get('ioc')}")
        print(f"   - Type:              {ioc.get('ioc_type')}")
        print(f"   - Threat Type:       {ioc.get('threat_type')} ({ioc.get('threat_type_desc')})")
        print(f"   - Malware:           {ioc.get('malware_printable')}")
        print(f"   - Confidence Level:  {ioc.get('confidence_level')}")
        print(f"   - First Seen:        {ioc.get('first_seen')}")
        print(f"   - Reporter:          {ioc.get('reporter')}")
        print(f"   - Tags:              {ioc.get('tags')}")
        print(f"   - Reference Link:    {ioc.get('reference')}\n")
