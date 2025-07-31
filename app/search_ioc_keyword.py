from api_client_details import threatfox_post
from regex_validation import valid_ip, valid_domain

# define function to search IOCs by IP/Domain name
def search_ioc_by_keyword():
    keyword = input("\nEnter IOC you want to search using IP/Domain/etc.: ").strip()

    if not keyword:
        print("\n ❗❗: Please provide a keyword!")

    if not (is_valid_ip(keyword) or is_valid_domain(keyword)):
        print("❗❗: Please enter a valid IP address or domain.")
        return

    exact_match_of_ioc = input("Do you want an exact match of the IOC entered? true/false?: ")
    if exact_match_of_ioc not in ["true", "false"]:
        print("\n❗❗Please enter either 'true' or 'false'.\n")
        return

    query_params = {"query": "search_ioc", "search_term": keyword, "exact_match": exact_match_of_ioc}

    result = threatfox_post(query_params)

    if not result:
        return

    keyword_data = result.get("data")

    if not isinstance(keyword_data, list):
        print("\n❌ No results found for your search.\n")
        return

    print("\nHere is your IOC search result using the keyword entered\n")
    for ioc in keyword_data:
        print(f"IOC ID NO: {ioc['id']}")
        print(f"{ioc['ioc_type']}: {ioc['ioc']}")
        print(f"Description of IOC: {ioc['ioc_type_desc']}")
        print(f"Type of threat from IOC: {ioc['threat_type']} - {ioc['threat_type_desc']}")
        print(f"Malware name in IOC: {ioc['malware_printable']}")
        print(f"Level of malice carried: {ioc['confidence_level']}\n")
