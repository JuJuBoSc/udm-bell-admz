import asyncio
import random
import time
import os
import sys

from unifi.client import UnifiClient
from modem.client import ModemClient

MODEM_HOST          = os.getenv("MODEM_HOST",               "192.168.2.1")      # IP address of the HH4400
MODEM_CLIENT        = os.getenv("MODEM_CLIENT",             "192.168.2.254")    # IP address that the UDM will use temporaly to fix ADMZ
MODEM_NETMASK       = os.getenv("MODEM_NETMASK",            "255.255.255.0")    # Netmask of the mode, usually 255.255.255.0
MODEM_USERNAME      = os.getenv("MODEM_USERNAME",           "admin")            # Username of the modem (for HH4400 it's admin and cannot be changed)
MODEM_PASSWORD      = os.getenv("MODEM_PASSWORD",           "")                 # Password of the modem (used to connect on the web interface)
UNIFI_HOST          = os.getenv("UNIFI_HOST",               "")                 # IP address of the UDM
UNIFI_USERNAME      = os.getenv("UNIFI_USERNAME",           "")                 # Username to login on the UDM console (use local account)
UNIFI_PASSWORD      = os.getenv("UNIFI_PASSWORD",           "")                 # Password of the UDM console
UNIFI_WAN_NAME      = os.getenv("UNIFI_WAN_NAME",           "")                 # Name of the internet connection (typically WAN or WAN1)
RUN_ONCE_AND_EXIT   = bool(os.getenv("RUN_ONCE_AND_EXIT",   False))             # If set to true, run the check once and exit
CHECK_INTERVAL      = int(os.getenv("CHECK_INTERVAL",       60))                # Interval between each check in seconds

def generate_mac_address():
    return "00:00:FF:%02X:%02X:%02X" % (random.randint(0, 255),
                             random.randint(0, 255),
                             random.randint(0, 255))

def is_valid_wan_ip(wan_ip: str) -> bool:
    return wan_ip != None and \
        not wan_ip.startswith("192.168.") and \
        not wan_ip.startswith("169.0")

async def get_router_wan_ip(router: UnifiClient) -> str:
    try:
        wan_stat = await router.get_active_wan_stat()
        return wan_stat["wan_ip"]
    except Exception as exception:
        return None

async def set_router_wan_static_ip(router: UnifiClient, network_config: dict, ip: str, netmask: str, gateway: str, mac: str = None) -> bool:
    wan_network_id = network_config.get("_id")
    new_config = network_config.copy()
    new_config["wan_type"] = "static"
    new_config["wan_ip"] = ip
    new_config["wan_gateway"] = gateway
    new_config["wan_netmask"] = netmask
    new_config["mac_override_enabled"] = mac != None
    if mac != None:
        new_config["mac_override"]          = mac

    return await router.set_network_configuration_by_id(wan_network_id, new_config)

async def set_router_wan_dhcp(router: UnifiClient, network_config: dict, mac: str = None) -> bool:
    wan_network_id = network_config.get("_id")
    new_config = network_config.copy()
    new_config["wan_type"] = "dhcp"
    new_config["mac_override_enabled"] = mac != None
    if mac != None:
        new_config["mac_override"]          = mac
    return await router.set_network_configuration_by_id(wan_network_id, new_config)

async def fix_admz(modem: ModemClient, router: UnifiClient, network_config: dict) -> bool:
    print("Start fixing sequence...")

    new_router_mac = generate_mac_address()
    print(f"Using new mac address for router: {new_router_mac}")

    print(f"Set temporary router wan configuration to static ip: {MODEM_CLIENT}")
    try:
        await set_router_wan_static_ip(router, network_config, MODEM_CLIENT, MODEM_NETMASK, MODEM_HOST, mac=None)
    except Exception as exception:
        print("Unable to update router configuration")
        print(exception)
        return False

    print("Wait for the change to propagate...")
    timeout = time.time() + 60*5
    while True:
        await asyncio.sleep(5)
        if time.time() > timeout:
            print("Timeout while applying router network configuration!")
            return False
        if await get_router_wan_ip(router) == MODEM_CLIENT:
            print(f"Router network configuration properly applied!")
            break

    try:
        print("Re-login with the modem...")
        await modem.login()

        print("Register new router mac address for ADMZ...")
        await modem.set_admz_host(new_router_mac)
        await asyncio.sleep(5)

        print("Ensure ADMZ is enabled on modem...")
        await modem.set_admz_status(True)
        await asyncio.sleep(5)

        print("Ensure DHCP is enabled on modem...")
        await modem.set_dhcp_status(True)
        await asyncio.sleep(5)

        print("Flush DHCP leases on modem...")
        await modem.flush_dhcp_leases()
        await asyncio.sleep(5)
    except Exception as exception:
        print("Error while updating modem configuration:")
        print(exception)
        return False

    print("Reboot the modem...")
    await modem.reboot()

    print("Wait for the modem goes offline...")
    timeout = time.time() + 60*5
    while True:
        await asyncio.sleep(10)
        if time.time() > timeout:
            print("Timeout while waiting the modem to reboot!")
            return False
        if await modem.is_up():
            print("Modem is still online, waiting...")
            try:
                await modem.login()
                await modem.reboot()
            except:
                pass
        else:
            print("Modem is offline!")
            break

    print("Wait for the modem to come back online...")
    timeout = time.time() + 60*5
    while True:
        await asyncio.sleep(10)
        if time.time() > timeout:
            print("Timeout while waiting the modem to reboot!")
            return False
        if not await modem.is_up():
            print("Modem is still offline, waiting...")
        else:
            print("Modem is online!")
            break

    print("Set router wan configuration to dhcp with new mac address...")
    await set_router_wan_dhcp(router, network_config, mac=new_router_mac)

    print("Wait for the change to propagate...")
    timeout = time.time() + 60*5
    while True:
        await asyncio.sleep(10)
        if time.time() > timeout:
            print("Timeout while applying router network configuration!")
            return False
        active_wan_ip = await get_router_wan_ip(router)
        if active_wan_ip and active_wan_ip != MODEM_CLIENT:
            print(f"Router network configuration properly applied!")
            break

    print("Wait for a valid wan ip...")
    timeout = time.time() + 60*5
    while True:
        await asyncio.sleep(5)
        if time.time() > timeout:
            print("Timeout while waiting for a valid wan ip!")
            return False
        active_wan_ip = await get_router_wan_ip(router)
        if not active_wan_ip:
            print("No wan ip yet, waiting...")
            continue
        if is_valid_wan_ip(active_wan_ip):
            print(f"Received a valid wan ip: {active_wan_ip}, success!")
            break

    return True

async def work(modem: ModemClient, router: UnifiClient) -> None:
    if not await router.is_up():
        print("Unable to connect to the router, is it up?")
        return

    if not await router.is_authenticated():
        print("Not authenticated with the router, login in...")
        try:
            await router.login()
        except Exception as exception:
            print("Unable to login with the router")
            print(exception)
            return
        print("Logged in with the router!")

    if not await modem.is_up():
        print("Unable to connect to the modem, is it up?")
        return

    if not await modem.is_authenticated():
        print("Not authenticated with the modem, login in...")
        try:
            encryption_method = await modem.login_find_encryption()
            print(f"Logged in using encryption method: {encryption_method}")
        except Exception as exception:
            print("Unable to login with the modem")
            print(exception)
            return
        print("Logged in with the modem!")

    try:
        wan_network_config = await router.get_network_configuration_by_name(UNIFI_WAN_NAME)
        if not wan_network_config:
            raise Exception("Network config not found")
    except Exception as exception:
        print("Unable to get wan network configuration!")
        print("Either the router is still loading, or your configuration is incorrect.")
        return

    wan_ip = await get_router_wan_ip(router)
    if not wan_ip:
        print(f"No wan ip found on the router, nothing to do...")
        return

    if not is_valid_wan_ip(wan_ip):
        print(f"Got invalid wan ip: {wan_ip}, ADMZ is fucked up!")
        await fix_admz(modem, router, wan_network_config)
        return

    print(f"Wan ip is: {wan_ip}, everything looks good!")
    return


def startup_checks():
    # Required environment variables
    REQUIRED_ENV_VARS = [
        "MODEM_PASSWORD",
        "UNIFI_HOST",
        "UNIFI_USERNAME",
        "UNIFI_PASSWORD",
        "UNIFI_WAN_NAME",
    ]
    missing_vars = []

    for var in REQUIRED_ENV_VARS:
        if globals()[var] is None or globals()[var] == "":
            missing_vars.append(var)

    if missing_vars:
        print(f"Error: Missing required environment variables: {', '.join(missing_vars)}")
        sys.exit(1)

    print("All required environment variables are set.")
    print(f"  MODEM_HOST        = {MODEM_HOST}")
    print(f"  MODEM_CLIENT      = {MODEM_CLIENT}")
    print(f"  MODEM_NETMASK     = {MODEM_NETMASK}")
    print(f"  MODEM_USERNAME    = {MODEM_USERNAME}")
    print(f"  MODEM_PASSWORD    = (hidden)")
    print(f"  UNIFI_HOST        = {UNIFI_HOST}")
    print(f"  UNIFI_USERNAME    = {UNIFI_USERNAME}")
    print(f"  UNIFI_PASSWORD    = (hidden)")
    print(f"  UNIFI_WAN_NAME    = {UNIFI_WAN_NAME}")
    print(f"  CHECK_INTERVAL    = {CHECK_INTERVAL}")
    print(f"  RUN_ONCE_AND_EXIT = {RUN_ONCE_AND_EXIT}")
    print("")

async def main() -> None:
    startup_checks()
    async with ModemClient(MODEM_HOST, MODEM_USERNAME, MODEM_PASSWORD, verify_ssl=False) as modem, \
        UnifiClient(UNIFI_HOST, UNIFI_USERNAME, UNIFI_PASSWORD) as router:
        while True:
            try:
                await work(modem, router)
            except Exception as exception:
                print("Exception during work sequence:")
                print(exception)
            if RUN_ONCE_AND_EXIT:
                print("RUN_ONCE_AND_EXIT enabled, exiting now...")
                break
            await asyncio.sleep(CHECK_INTERVAL)

asyncio.run(main())