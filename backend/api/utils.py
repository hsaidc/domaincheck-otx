from dns.resolver import Resolver, NXDOMAIN, YXDOMAIN, LifetimeTimeout, NoAnswer, NoNameservers, NotAbsolute, NoRootSOA

from OTXv2 import OTXv2, IndicatorTypes, BadRequest
from datetime import datetime

API_KEY = 'YOUR_OTX_API_KEY'
print("API KEY:", API_KEY)

def parse_pulse_info(pulse_info):
    """Parses the details of 'Pulse Info' obtained from OTX query.

    Args:
        pulse_info (list): A list of pulse information dictionaries.

    Returns:
        list: A list of parsed pulse data, each containing:
            - id: Pulse ID
            - name: Pulse name
            - description: Pulse description
            - modified: Pulse modification timestamp
            - created: Pulse creation timestamp
            - references: Pulse references
            - adversary: Pulse adversary
            - malware_families: Pulse malware families
            - targeted_countries: Pulse targeted countries
            - attack_ids: Pulse attack IDs
            - pulse_address: URL to the pulse on OTX
            - number_of_targeted_countries: Number of targeted countries
            - number_of_attacks: Number of attacks
    """

    interested_fields = [
        'id',
        'name',
        'description',
        'modified',
        'created',
        'references',
        'adversary',
        'malware_families',
        'targeted_countries',
        'attack_ids',
    ]

    data = []

    for elem in pulse_info:
        tmp = {}
        for field in interested_fields:
            tmp[field] = elem[field]

        # Add custom fields to represent data better.
        tmp['pulse_address'] = f'https://otx.alienvault.com/pulse/{tmp["id"]}'
        tmp['number_of_targeted_countries'] = len(tmp['targeted_countries'])
        tmp['number_of_attacks'] = len(tmp['attack_ids'])

        data.append(tmp)

    return data


def parse_otx_query_result(result, language):
    """Parses the result obtained from OTX query.

    Args:
        result (dict): The result dictionary from the OTX query.

    Returns:
        dict: A dictionary containing:
            - address: The queried address
            - is_malicious: True if malicious, False if not, "unknown" if unknown
            - validation: Validation information (if available)
            - data: Parsed pulse data (if available)
            - message: A message describing the result

    Raises:
        ValueError: If the result is not in the expected format.
    """
    #  Check whether result is in the correct format or not
    assert isinstance(result, dict)

    # Check whether validation key is in the result dict
    # If it is not, then result might not be in the required format
    if 'validation' in result.keys():
        validation = result['validation']
        if validation:
            if language == "en":
                message = 'The queried address has been validated by certain authorities and is on the list of trusted addresses.'
            else:
                message = 'Sorgulanan adres belirli makamlar tarafından doğrulanmıştır ve güvenilir adresler listesinde yer almaktadır.'

            return {
                'address': result['indicator'],
                'is_malicious': False,
                'validation': result['validation'],
                'message': message
            }
        else:
            if result['pulse_info']['count'] > 0:
                data = parse_pulse_info(result['pulse_info']['pulses'])
                if language == "en":
                    message = 'The queried address has a bad reputation in the OTX database. Be careful!'
                else:
                    message = 'Sorgulanan adres OTX veritabanında kötü bir itibara sahiptir. Dikkatli olunuz!'

                return {
                    'address': result['indicator'],
                    'is_malicious': True,
                    'data': data,
                    'message': message
                }
            else:
                if language == "en":
                    message = 'No verifying source or OTX pulse record indicating that it is harmful could be reached for the queried address. Be careful!'
                else:
                    message = 'Sorgulanan adres ile ilgili herhangi bir doğrulayıcı kaynağa veya zararlı olduğunu gösteren OTX pulse kaydına ulaşılamamıştır. Dikkatli olunuz!'
                return {
                    'address': result['indicator'],
                    'is_malicious': 'unknown',
                    'data': [],
                    'message': message
                }

    else:
        raise ValueError('Result is not in the required format!')


def is_malicious(address, indicator_type, language="en"):
    """Queries the reputation of an address using the AlienVault OTXv2 API.

    Args:
        address (str): The address to query, either an IP address or domain/hostname.
        indicator_type (str): The type of indicator, either 'IPv4', 'IPv6', or 'domain_or_host'.

    Returns:
        dict: A dictionary containing information about the address's reputation, including:
            - address: The queried address.
            - is_malicious: True if malicious, False if not, "unknown" if unknown, or "bad_request" if there was an error.
            - validation: Validation information (if available).
            - data: Parsed pulse data (if available).
            - message: A message describing the result.

    Raises:
        BadRequest: If the provided address is not valid.
        Exception: If there is an unexpected error.
    """    # Create an instance of OTX class to query ip/domain/host security.
    otx = OTXv2(API_KEY)

    try:
        if indicator_type == 'IPv4':
            ipv4_result = otx.get_indicator_details_by_section(
                IndicatorTypes.IPv4, address, 'general')
            data = parse_otx_query_result(ipv4_result, language)

            return data

        elif indicator_type == 'IPv6':
            ipv6_result = otx.get_indicator_details_by_section(
                IndicatorTypes.IPv6, address, 'general')
            data = parse_otx_query_result(ipv6_result, language)

            return data

        elif indicator_type == 'domain_or_host':
            host_result = otx.get_indicator_details_by_section(
                IndicatorTypes.HOSTNAME, address, 'general')
            host_data = parse_otx_query_result(host_result, language)

            domain_result = otx.get_indicator_details_by_section(
                IndicatorTypes.DOMAIN, address, 'general')
            domain_data = parse_otx_query_result(domain_result, language)

            # print(host_result)
            # print("----------------")
            # print(domain_result)
            # If either one of the queries indicates that address is malicious then
            # Return as malicious even if other query says the opposite
            # In order not to take any responsibility
            if host_data['is_malicious'] == True:
                data = host_data
            elif domain_data['is_malicious'] == True:
                data = domain_data
            # If both of them not malicious and one of them states that it is whitelisted
            # Then return as not malicious.
            elif host_data['is_malicious'] == False:
                data = host_data
            elif domain_data['is_malicious'] == False:
                data = domain_data
            # If both of the queries does not have adequate information then return the result
            #  as unknown. Unknown status includes explanation about inadequate status of the address
            elif host_data['is_malicious'] == "unknown" and domain_data['is_malicious'] == "unknown":
                data = host_data

            return data

        else:
            data = {
                'address': address,
                'is_malicious': "bad_request",
                'message': 'Provided indicator type is neither IP nor domain/hostname!'
            }

            return data

    # Catches BadRequest error raised from OTX incase provided address is not valid
    except BadRequest:
        data = {
            'is_malicious': 'bad_request',
            'message': 'Provided address is neither a valid IP address nor a valid domain/hostname!'
        }

        return data

    # Catches other exceptions. Bad practice, update.
    except Exception as e:
        data = {
            'is_malicious': 'bad_request',
            'message': 'An error occured! Please contact admin if continues...'
        }

        return data


def dns_enumeration(address):
    """Performs DNS enumeration and returns server responses with expiration dates.

    Args:
        address (str): The domain name or IP address to query.

    Returns:
        list: A list of dictionaries containing DNS enumeration results, with each dictionary containing:
            - record_type (str): The type of DNS record queried.
            - status (bool): True if the query was successful, False otherwise.
            - data (list): A list of answer strings if successful, or an error message if not.
            - expiration (datetime.datetime): The expiration time of the DNS record (if available).
    """
    # Record types to be queried
    # record_types = ["A", "A6", "AAAA", "AFSDB", "AMTRELAY", "APL", "AVC", "CAA", "CDNSKEY", "CDS", "CERT", "CNAME", "CSYNC", "DHCID", "DLV", "DNAME", "DNSKEY", "DS", "EUI48", "EUI64", "GPOS", "HINFO", "HIP", "HTTPS", "IPSECKEY", "ISDN",  "KEY", "KX", "L32", "L64", "LOC", "LP", "MB", "MD",
    #                 "MF", "MG", "MINFO", "MR", "MX", "NAPTR", "NID", "NINFO", "NS", "NSAP", "NSAP_PTR", "NSEC", "NSEC3", "NSEC3PARAM", "NULL", "NXT", "OPENPGPKEY",  "PTR", "PX", "RP", "RRSIG", "RT", "SIG", "SMIMEA", "SOA", "SPF", "SRV", "SSHFP", "SVCB", "TA",  "TLSA",  "TXT", "UNSPEC", "URI", "WKS", "X25", "ZONEMD"]

    # Much shorter list of most commonly used/required record types.
    record_types = ["A", "AAAA", "CNAME", "NS", "MX", "TXT", "SOA"]
    # Instantiate dns.resolver.Resolver class
    resolver = Resolver()
    # A dictionary to store results
    DNS_ENUMERATION_RESULTS = []

    # Query for each record type separately
    for record_type in record_types:
        # print(record_type)
        try:
            response = resolver.resolve(address, record_type)
            # Check if there is any answer
            if len(response.chaining_result.answer) > 0:
                answers = [str(elem)
                           for elem in response.chaining_result.answer]
                DNS_ENUMERATION_RESULTS.append({
                    "record_type": record_type,
                    "status": True,
                    "data": answers,
                    "expiration": datetime.fromtimestamp(response.expiration)
                })
        except (NXDOMAIN, YXDOMAIN, LifetimeTimeout, NoAnswer, NoNameservers, NotAbsolute, NoRootSOA) as e:
            DNS_ENUMERATION_RESULTS.append({
                "record_type": record_type,
                "status": False,
                "data": str(e)
            })
        except Exception as e:
            print("Error:", e)

    # print(DNS_ENUMERATION_RESULTS)
    return DNS_ENUMERATION_RESULTS
