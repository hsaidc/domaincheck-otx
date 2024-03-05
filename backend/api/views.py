from urllib.parse import urlparse
from ipaddress import ip_address, IPv4Address

from django.http import JsonResponse

from rest_framework.permissions import AllowAny
from rest_framework.decorators import api_view, permission_classes

from api.utils import is_malicious, dns_enumeration


@api_view(['GET'])
@permission_classes([AllowAny])
def otx(request):
    """Handles GET requests to query the reputation of an IP address or domain/hostname using AlienVault OTX.

    Accepts an 'address' query parameter and returns a JSON response indicating whether the address is malicious.
    Address should be a valid IPv4 address or domain/hostname
    """
    try:
        address = request.query_params['address']
        language = request.query_params['language']

        # Check whether queried address successfully obtained or not
        if address:
            # Check whether provided address is an IPv4 address
            # Address might be a valid IPv4 address if it is numeric
            # after dots removed from the string
            if address.replace('.', '').isnumeric():
                # Even if address is numeric, it might not be a valid IPv4 address
                # Utilize ipaddress package to check validity of provided IP
                if isinstance(ip_address(address), IPv4Address):
                    data = is_malicious(address, 'IPv4', language=language)
                    return JsonResponse({'status': True, 'data': data}, status=200)
                else:
                    raise ValueError("Not a valid ip address!")

            # Domain name control should be improved further than searching for at least one dot
            elif len(address.split('.')) >= 2:
                domain = address.split('//')[-1].split("/")[0]
                data = is_malicious(
                    domain, 'domain_or_host', language=language)
                return JsonResponse({'status': True, 'data': data}, status=200)

            else:
                raise ValueError('Either not an ip or domain/host name!')

    except ValueError:
        return JsonResponse({'status': False, 'data': str(ValueError)}, status=200)

    except Exception as e:
        return JsonResponse({'status': False, 'data': str(e)}, status=200)


@api_view(['GET'])
@permission_classes([AllowAny])
def dns(request):
    """Handles GET requests to perform DNS enumeration on a domain name.

    Accepts an 'address' query parameter and returns a JSON response containing DNS enumeration results.
    Address should be a valid domain/hostname.
    """
    try:
        address = request.query_params['address']
        language = request.query_params['language']

        # Check whether queried address successfully obtained or not
        # print(address)
        if address:
            # Check whether provided address is an IPv4 address
            # Address might be a valid IPv4 address if it is numeric
            # after dots removed from the string
            if address.replace('.', '').isnumeric():
                raise ValueError(
                    'Not a valid domain name! You probably provided an IP address')

            # Domain name control should be improved further than searching for at least one dot
            elif len(address.split('.')) >= 2:
                domain = address.split('//')[-1].split("/")[0]
                if ("www." in domain):
                    domain = domain[4:]
                # print(domain)
                data = dns_enumeration(domain)
                # print(data)
                return JsonResponse({'status': True, 'data': data}, status=200)

            else:
                raise ValueError('Not a valid domain name!')

    except ValueError:
        return JsonResponse({'status': False, 'data': str(ValueError)}, status=200)

    except Exception as e:
        return JsonResponse({'status': False, 'data': str(e)}, status=200)


@api_view(['GET'])
def home(request):
    """Handles get request sent to /api home.

    A dummy handler to check whether server is up or down.
    """
    return JsonResponse({'status': True, 'data': "Up!"}, status=200)
