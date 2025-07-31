# Gets data about different indicators of compromise(IOCs)
# Data could be about recent IOCs from ThreatFox's dataset or narrowing down
# search using days that IOC was first seen(max 7 days)

# import base function to use for querying ThreatFox API endpoints
from api_client_details import threatfox_post

# define function to get latest IOCs 
def get_recent_iocs():
    try:
        day = int(input("Enter Number of days to filter IOCs for (based on first_seen) Min: 1, Max: 7, Default: 3: "))
        if not (1 <= day <= 7):
            print("\n ===================================")
            print("❗❗: Please enter a number between 1 & 7.")
            print("=================================== \n")
            return
    except ValueError:
        print("\n ===================================")
        print("⛔ Invalid input. Only a number between 1 & 7 is allowed")
        print("=================================== \n")
        return

    query_params = {"query": "get_iocs", "days": day}
    res = threatfox_post(query_params)

    if not res:
        print("Error fetching data from ThreatFox.\n")
        return

    data = res.get("data", [])
    if not data:
        print("Hmmm🧐...No recent IOCs found.")
        return

    print(f"\nHere are {len(data)} IOCs seen in the past {day} day/days🔎:")

    for index, ioc in enumerate(data, start=1):
        print(f" 💣 IOC #{index}\n")
        print(f"   - IOC id:            {ioc.get('id')}")
        print(f"   - IOC Value:         {ioc.get('ioc')}")
        print(f"   - Type:              {ioc.get('ioc_type')}")
        print(f"   - Threat Type:       {ioc.get('threat_type')} ({ioc.get('threat_type_desc')})")
        print(f"   - Malware:           {ioc.get('malware_printable')}")
        print(f"   - Threat level:      {ioc.get('confidence_level')}")
        print(f"   - Reference Link:    {ioc.get('reference')}")
        print(f"   - First Seen:        {ioc.get('first_seen')}\n")
