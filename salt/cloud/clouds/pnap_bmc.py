# -*- coding: utf-8 -*-
"""
phoenixNAP BMC Cloud Module
===========================

The phoenixNAP cloud module is used to interact with phoenixNAP Bare Metal Cloud:
https://phoenixnap.com/bare-metal-cloud

Use of this module requires the ``client_id`` and ``client_secret`` parameter to be set.
Set up the cloud configuration at ``/etc/salt/cloud.providers`` or
``/etc/salt/cloud.providers.d/pnap.conf``:

.. code-block:: yaml
    # Note: This example is for /etc/salt/cloud.providers
    # or any file in the
    # /etc/salt/cloud.providers.d/ directory.
    pnap-config:
        client_id: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
        client_secret: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
        driver: pnap_bmc


NEEEEEEEEEEEEEEED TO BE UPDATED
:depends: libcloud >= 1.2.1
"""
# Import python libs
from __future__ import absolute_import, print_function, unicode_literals

import logging
import pprint
from base64 import standard_b64encode

import salt.config as config
import salt.utils.cloud
import salt.utils.files

# pylint: disable=function-redefined
from salt.cloud.libcloudfuncs import *  # pylint: disable=wildcard-import,unused-wildcard-import
from salt.exceptions import SaltCloudConfigError, SaltCloudSystemExit
from salt.utils.functools import namespaced_function

# Import libcloud
try:
    import libcloud
    from libcloud.compute.types import Provider
    from libcloud.compute.providers import get_driver

    HAS_LIBCLOUD = True
except ImportError:
    HAS_LIBCLOUD = False


get_location = namespaced_function(get_location, globals())
get_size = namespaced_function(get_size, globals())
get_image = namespaced_function(get_image, globals())
avail_locations = namespaced_function(avail_locations, globals())
avail_images = namespaced_function(avail_images, globals())
avail_sizes = namespaced_function(avail_sizes, globals())
script = namespaced_function(script, globals())
#destroy = namespaced_function(destroy, globals())
list_nodes = namespaced_function(list_nodes, globals())
list_nodes_full = namespaced_function(list_nodes_full, globals())
list_nodes_select = namespaced_function(list_nodes_select, globals())
show_instance = namespaced_function(show_instance, globals())
get_node = namespaced_function(get_node, globals())

# Get logging started
log = logging.getLogger(__name__)

__virtualname__ = "pnap_bmc"


def __virtual__():
    """
    Set up the libcloud functions and check for pnap_bmc configurations.
    """
    if get_configured_provider() is False:
        return False

    if get_dependencies() is False:
        return False

    for provider, details in __opts__["providers"].items():
        if "pnap_bmc" not in details:
            continue

    return __virtualname__


def _get_active_provider_name():
    try:
        return __active_provider_name__.value()
    except AttributeError:
        return __active_provider_name__


def get_configured_provider():
    """
    Return the first configured instance.
    """
    return config.is_provider_configured(
        __opts__,
        _get_active_provider_name() or "pnap_bmc",
        ("client_id", "client_secret"),
    )


def get_dependencies():
    """
    Warn if dependencies aren't met.
    """
    deps = {"libcloud": HAS_LIBCLOUD}
    return config.check_driver_dependencies(__virtualname__, deps)


def get_conn():
    """
    Return a conn object for the passed VM data
    """
    vm_ = get_configured_provider()
    driver = get_driver(Provider.PNAP_BMC)

    client_id = config.get_cloud_config_value("client_id", vm_, __opts__)
    client_secret = config.get_cloud_config_value("client_secret", vm_, __opts__)

    return driver(client_id, client_secret)


def stop(name, call=None):
    """
    Stop a VM in phoenixNAP.

    name:
        The name of the VM to stop.

    CLI Example:

    .. code-block:: bash

        salt-cloud -a stop vm_name
    """
    if call != "action":
        raise SaltCloudSystemExit("The stop action must be called with -a or --action.")

    data = show_instance(name, call="action")  # pylint: disable=not-callable
    if data.get("state") == "stopped":
        return {
            "success": True,
            "action": "stop",
            "status": data["state"],
            "msg": "Server is already stopped.",
        }

    conn = get_conn()
    node = get_node(conn, name)  # pylint: disable=not-callable
    log.debug("Node of Cloud VM: %s", node.name)
    status = conn.stop_node(node)

    __utils__["cloud.fire_event"](
        "event",
        "stop instance",
        "salt/cloud/{0}/stopping".format(node.name),
        args={"name": node.name},
        sock_dir=__opts__["sock_dir"],
        transport=__opts__["transport"],
    )
    log.debug("Status of Cloud VM: %s", status)

    return status


def start(name, call=None):
    """
    Start a VM in phoenixNAP.

    name:
        The name of the VM to start.

    CLI Example:

    .. code-block:: bash

        salt-cloud -a start vm_name
    """
    if call != "action":
        raise SaltCloudSystemExit(
            "The start action must be called with -a or --action."
        )

    data = show_instance(name, call="action")  # pylint: disable=not-callable
    if data.get("state") == "running":
        return {
            "success": True,
            "action": "start",
            "status": data["state"],
            "msg": "Server is already running.",
        }

    conn = get_conn()
    node = get_node(conn, name)  # pylint: disable=not-callable
    log.debug("Node of Cloud VM: %s", node.name)
    status = conn.start_node(node)

    __utils__["cloud.fire_event"](
        "event",
        "start instance",
        "salt/cloud/{0}/starting".format(node.name),
        args={"name": node.name},
        sock_dir=__opts__["sock_dir"],
        transport=__opts__["transport"],
    )
    log.debug("Status of Cloud VM: %s", status)

    return status


def reboot(name, call=None):
    """
    Reboot a VM in phoenixNAP.

    name:
        The name of the VM to reboot.

    CLI Example:

    .. code-block:: bash

        salt-cloud -a reboot vm_name
    """
    if call != "action":
        raise SaltCloudSystemExit(
            "The reboot action must be called with -a or --action."
        )
    data = show_instance(name, call="action")  # pylint: disable=not-callable
    if data.get("state") == "stopped":
        return {
            "success": True,
            "action": "stop",
            "status": data["state"],
            "msg": "Server is already stopped.",
        }

    conn = get_conn()
    node = get_node(conn, name)  # pylint: disable=not-callable
    log.debug("Node of Cloud VM: %s", node.name)
    status = conn.reboot_node(node)

    __utils__["cloud.fire_event"](
        "event",
        "reboot instance",
        "salt/cloud/{0}/rebooting".format(node.name),
        args={"name": node.name},
        sock_dir=__opts__["sock_dir"],
        transport=__opts__["transport"],
    )
    log.debug("Status of Cloud VM: %s", status)

    return status


def power_off(name, call=None):
    """
    Power Off a VM in phoenixNAP.
    (which is equivalent to cutting off electricity from the server).
    We strongly advise you to use the stop in order to minimize
    any possible data loss or corruption.

    name:
        The name of the VM to power off.

    CLI Example:

    .. code-block:: bash

        salt-cloud -a power_off vm_name
    """
    if call != "action":
        raise SaltCloudSystemExit(
            "The power_off action must be called with -a or --action."
        )
    data = show_instance(name, call="action")  # pylint: disable=not-callable
    if data.get("state") == "stopped":
        return {
            "success": True,
            "action": "power_off",
            "status": data["state"],
            "msg": "Server is already powered off.",
        }

    conn = get_conn()
    node = get_node(conn, name)  # pylint: disable=not-callable
    log.debug("Node of Cloud VM: %s", node.name)
    status = conn.ex_power_off_node(node)

    __utils__["cloud.fire_event"](
        "event",
        "power off instance",
        "salt/cloud/{0}/powering off".format(node.name),
        args={"name": node.name},
        sock_dir=__opts__["sock_dir"],
        transport=__opts__["transport"],
    )
    log.debug("Status of Cloud VM: %s", status)

    return status


def create(vm_):
    """
    Create a single VM from a data dict
    """
    try:
        # Check for required profile parameters before sending any API calls.
        if (
            vm_["profile"]
            and config.is_profile_configured(
                __opts__, __active_provider_name__ or "pnap_bmc", vm_["profile"]
            )
            is False
        ):
            return False
    except AttributeError:
        pass

    __utils__["cloud.fire_event"](
        "event",
        "starting create",
        "salt/cloud/{0}/creating".format(vm_["name"]),
        args=__utils__["cloud.filter_event"](
            "creating", vm_, ["name", "profile", "provider", "driver"]
        ),
        sock_dir=__opts__["sock_dir"],
        transport=__opts__["transport"],
    )

    log.info("Creating Cloud VM %s", vm_["name"])
    conn = get_conn()

    image = get_image(conn, vm_)
    ssh_user = config.get_cloud_config_value("ssh_username", vm_, __opts__)
    if ssh_user is None:
        if image.name.startswith("ubuntu"):
            ssh_user = "ubuntu"
        elif image.name.startswith("centos"):
            ssh_user = "centos"
        else:
            ssh_user = "admin"

    ip_blocks_configuration_type = config.get_cloud_config_value(
        "ip_blocks_configuration_type", vm_, __opts__
    )
    ip_blocks_ids = config.get_cloud_config_value("ip_blocks_ids", vm_, __opts__)
    management_access_allowed_ips = config.get_cloud_config_value(
        "management_access_allowed_ips", vm_, __opts__
    )
    gateway_address = config.get_cloud_config_value("gateway_address", vm_, __opts__)
    private_network_configuration_type = config.get_cloud_config_value(
        "private_network_configuration_type", vm_, __opts__
    )
    private_networks = config.get_cloud_config_value("private_networks", vm_, __opts__)
    public_networks = config.get_cloud_config_value("public_networks", vm_, __opts__)
    tags = config.get_cloud_config_value("tags", vm_, __opts__)
    description = config.get_cloud_config_value("description", vm_, __opts__)
    ssh_keys = _get_ssh_keys(
        config.get_cloud_config_value("ssh_pubkey_path", vm_, __opts__)
    )
    install_default_ssh_keys = config.get_cloud_config_value(
        "install_default_ssh_keys", vm_, __opts__
    )
    ssh_key_ids = config.get_cloud_config_value("ssh_key_ids", vm_, __opts__)
    reservation_id = config.get_cloud_config_value("reservation_id", vm_, __opts__)
    pricing_model = config.get_cloud_config_value("pricing_model", vm_, __opts__)
    network_type = config.get_cloud_config_value("network_type", vm_, __opts__)
    rdp_allowed_ips = config.get_cloud_config_value("rdp_allowed_ips", vm_, __opts__)
    install_os_to_ram = config.get_cloud_config_value(
        "install_os_to_ram", vm_, __opts__
    )
    cloud_init = _get_cloud_init(
        config.get_cloud_config_value("cloud_init_path", vm_, __opts__)
    )
    force = config.get_cloud_config_value("force", vm_, __opts__, False)
    netris_controller = config.get_cloud_config_value("netris_controller", vm_, __opts__)
    netris_softgate = config.get_cloud_config_value("netris_softgate", vm_, __opts__)
    storage_configuration = config.get_cloud_config_value("storage_configuration", vm_, __opts__)

    kwargs = {
        "name": vm_["name"],
        "image": image,  # pylint: disable=not-callable
        "size": get_size(conn, vm_),  # pylint: disable=not-callable
        "location": get_location(conn, vm_),  # pylint: disable=not-callable
        "ex_ip_blocks_configuration_type": ip_blocks_configuration_type,
        "ex_ip_blocks_ids": ip_blocks_ids,
        "ex_management_access_allowed_ips": management_access_allowed_ips,
        "ex_gateway_address": gateway_address,
        "ex_private_network_configuration_type": private_network_configuration_type,
        "ex_private_networks": private_networks,
        "ex_public_networks": public_networks,
        "ex_tags": tags,
        "ex_description": description,
        "ex_ssh_keys": ssh_keys,
        "ex_install_default_ssh_keys": install_default_ssh_keys,
        "ex_ssh_key_ids": ssh_key_ids,
        "ex_reservation_id": reservation_id,
        "ex_pricing_model": pricing_model,
        "ex_network_type": network_type,
        "ex_rdp_allowed_ips": rdp_allowed_ips,
        "ex_install_os_to_ram": install_os_to_ram,
        "ex_cloud_init_user_data": cloud_init,
        "ex_force":force,
        "ex_netris_controller": netris_controller,
        "ex_netris_softgate": netris_softgate,
        "ex_storage_configuration": storage_configuration,
    }

    ret = __utils__["cloud.bootstrap"](vm_, __opts__)
    # return ret
    # return {
    #             "debug": force,
    #             # "action": 'xxx',
    #             # "status": 'yyy',
    #             # "msg": "Server is already powered off.",
    #         }
    __utils__["cloud.fire_event"](
        "event",
        "requesting instance",
        "salt/cloud/{0}/requesting".format(vm_["name"]),
        args=__utils__["cloud.filter_event"](
            "requesting", vm_, ["name", "profile", "provider", "driver"]
        ),
        sock_dir=__opts__["sock_dir"],
        transport=__opts__["transport"],
    )

    try:
        node_data = conn.create_node(**kwargs)
    except Exception as exc:  # pylint: disable=broad-except
        log.error(
            "Error creating %s on phoenixNAP\n\n"
            "The following exception was thrown by libcloud when trying to "
            "run the initial deployment: \n%s",
            vm_["name"],
            exc,
            exc_info_on_loglevel=logging.DEBUG,
        )
        return False

    node_dict = show_instance(node_data.name, "action")  # pylint: disable=not-callable

    private_key = config.get_cloud_config_value("ssh_privkey_path", vm_, __opts__)
    if private_key is not None:
        private_key = os.path.expanduser(private_key)

    vm_["ssh_host"] = node_dict["public_ips"][0]
    vm_["key_filename"] = private_key
    vm_["ssh_username"] = ssh_user

    ret = __utils__["cloud.bootstrap"](vm_, __opts__)
    if __opts__["deploy"]:
        node_dict["state"] = "running"
    ret.update(node_dict)
    log.info("Created Cloud VM '%s'", vm_["name"])
    log.trace("'%s' VM creation details:\n%s", vm_["name"], pprint.pformat(node_dict))

    __utils__["cloud.fire_event"](
        "event",
        "created instance",
        "salt/cloud/{0}/created".format(vm_["name"]),
        args=__utils__["cloud.filter_event"](
            "created", vm_, ["name", "profile", "provider", "driver"]
        ),
        sock_dir=__opts__["sock_dir"],
        transport=__opts__["transport"],
    )

    return ret


def destroy(vm_, kwargs=None, call=None):
    """
    Destroy a node.

    CLI Example:

    .. code-block:: bash

        salt-cloud -a destroy myserver delete_ip_blocks=True -y
    """
    if call == "function":
        raise SaltCloudSystemExit(
            "The destroy action must be called with -d, --destroy, -a or --action."
        )

    __utils__["cloud.fire_event"](
        "event",
        "destroying instance",
        f"salt/cloud/{vm_}/destroying",
        args={"name": vm_},
        sock_dir=__opts__["sock_dir"],
        transport=__opts__["transport"],
    )

    if not kwargs or "delete_ip_blocks" not in kwargs:
        log.error("A delete_ip_blocks argument is required.")
        return False
    
    delete_ip_blocks = kwargs.get('delete_ip_blocks', False)
    
    conn = get_conn()
    node = get_node(conn, vm_)
    node_data = conn.destroy_node(node, delete_ip_blocks)

    __utils__["cloud.fire_event"](
        "event",
        "destroyed instance",
        "salt/cloud/{}/destroyed".format(vm_),
        args={"name": vm_},
        sock_dir=__opts__["sock_dir"],
        transport=__opts__["transport"],
    )

    return node_data


def set_tags(name=None, kwargs=None, call=None):
    """
    Overwrites tags assigned for Server and unassigns any tags not part of the request.

    name:
        The name of the Server.
    tags:
        Tags to assign to Server

    CLI Example:

    .. code-block:: bash

        salt-cloud -a set_tags vm_name tags='{"name": "salt", "value": "test"}'
    """
    if call != "action":
        raise SaltCloudSystemExit(
            "The set_tags action must be called with -a or --action."
        )

    if not kwargs or "tags" not in kwargs:
        log.error("A tags argument is required.")
        return False

    tags = _validate_dict_type("tags", kwargs["tags"])
    conn = get_conn()
    node = get_node(conn, name)
    node_data = conn.ex_edit_node_tags(node, tags)
    return show_instance(node_data.name, "action")


def add_ip_block(name=None, kwargs=None, call=None):
    """
    Adds an IP block to this server. No actual configuration is performed on the operating system.
    BMC configures exclusively the networking devices in the datacenter infrastructure.
    Manual network configuration changes in the operating system of this server are required.

    name:
        The name of the Server.
    ip_block_id:
        The IP Block identifier.
    vlan_id:
        The VLAN on which this IP block has been configured within the network switch.

    CLI Example:

    .. code-block:: bash

        salt-cloud -a add_ip_block vm_name ip_block_id=456
    """
    if call != "action":
        raise SaltCloudSystemExit(
            "The add_ip_block action must be called with -a or --action."
        )

    if "ip_block_id" not in kwargs:
        log.error("A ip_block_id is required.")
        return False

    vlan_id = kwargs.get("vlan_id", None)
    conn = get_conn()
    node = get_node(get_conn(), name)
    return conn.ex_edit_node_add_ip_block(node, kwargs["ip_block_id"], vlan_id=vlan_id)

def remove_ip_block(name=None, kwargs=None, call=None):
    """
    Removes the IP block from the server. No actual configuration is performed on the operating system.
    BMC configures exclusively the networking devices in the datacenter infrastructure.
    Manual network configuration changes in the operating system of this server are required.
    This is an advanced network action that can make your server completely unavailable over any network.
    Make sure this server is reachable over remote console for guaranteed access in case of misconfiguration.

    name:
        The name of the Server.
    ip_block_id:
        The IP Block identifier.
    delete_ip_block:
        Determines whether the IP blocks assigned to the server should be deleted or not.
        Default value: False

    CLI Example:

    .. code-block:: bash

        salt-cloud -a remove_ip_block vm_name ip_block_id=456
    """
    if call != "action":
        raise SaltCloudSystemExit(
            "The remove_ip_block action must be called with -a or --action."
        )

    if "ip_block_id" not in kwargs:
        log.error("A ip_block_id is required.")
        return False

    delete_ip_block = kwargs.get("delete_ip_block", False)
    conn = get_conn()
    node = get_node(conn, name)
    return conn.ex_edit_node_remove_ip_block(
        node, kwargs["ip_block_id"], delete_ip_block
    )


def add_private_network(name=None, kwargs=None, call=None):
    """
    Adds the server to a private network.
    No actual configuration is performed on the operating system.
    BMC configures exclusively the networking devices in the datacenter infrastructure.
    Manual network configuration changes in the operating system of this server are required.
    If the network contains a membership of type 'storage',
    the first twelve IPs are already reserved by BMC and not usable.

    name:
        The name of the Server.
    private_network:
        Private network details of bare metal server.

    CLI Example:

    .. code-block:: bash

        salt-cloud -a add_private_network vm_name private_network='{"id": "123", "dhcp": false, "ips": ["10.0.0.1", "10.0.0.2"]}'
    """
    if call != "action":
        raise SaltCloudSystemExit(
            "The add_private_network action must be called with -a or --action."
        )

    if "private_network" not in kwargs:
        log.error("A private_network is required.")
        return False

    private_network = salt.utils.yaml.safe_load(kwargs["private_network"])
    if not isinstance(private_network, dict):
        raise SaltCloudConfigError("private_network should be provided as dictionary.")

    conn = get_conn()
    node = get_node(conn, name)
    return conn.ex_edit_node_add_private_network(node, private_network)


def remove_private_network(name=None, kwargs=None, call=None):
    """
    Removes the server from private network.
    No actual configuration is performed on the operating system.
    BMC configures exclusively the networking devices in the datacenter infrastructure.
    Manual network configuration changes in the operating system of this server are required.
    This is an advanced network action that can make your
    server completely unavailable over any network.
    Make sure this server is reachable over remote console
    for guaranteed access in case of misconfiguration.

    name:
        The name of the Server.
    private_network_id:
        The private network identifier.

    CLI Example:

    .. code-block:: bash

        salt-cloud -a remove_private_network vm_name private_network_id='123'
    """
    if call != "action":
        raise SaltCloudSystemExit(
            "The remove_private_network action must be called with -a or --action."
        )

    if "private_network_id" not in kwargs:
        log.error("A private_network_id is required.")
        return False

    conn = get_conn()
    node = get_node(conn, name)
    return conn.ex_edit_node_remove_private_network(node, kwargs["private_network_id"])


def add_public_network(name=None, kwargs=None, call=None):
    """
    Adds the server to a Public Network.
    No actual configuration is performed on the operating system.
    BMC configures exclusively the networking devices in the datacenter infrastructure.
    Manual network configuration changes in the operating system of this server are required.

    name:
        The name of the Server.
    public_network:
        Private network details of bare metal server.

    CLI Example:

    .. code-block:: bash

        salt-cloud -a add_public_network vm_name public_network='{"id": "123", "ips": ["10.111.14.112", "10.111.14.113"]}'
    """
    if call != "action":
        raise SaltCloudSystemExit(
            "The add_public_network action must be called with -a or --action."
        )

    if "public_network" not in kwargs:
        log.error("A public_network is required.")
        return False

    private_network = salt.utils.yaml.safe_load(kwargs["public_network"])
    if not isinstance(private_network, dict):
        raise SaltCloudConfigError("public_network should be provided as dictionary.")

    conn = get_conn()
    node = get_node(conn, name)
    return conn.ex_edit_node_add_public_network(node, private_network)


def remove_public_network(name=None, kwargs=None, call=None):
    """
    Removes the server from the Public Network.
    No actual configuration is performed on the operating system.
    BMC configures exclusively the networking devices in the datacenter infrastructure.
    Manual network configuration changes in the operating system of this server are required.
    This is an advanced network action that can make
    your server completely unavailable over any network.
    Make sure this server is reachable over remote console
    for guaranteed access in case of misconfiguration.

    name:
        The name of the Server.
    public_network_id:
        The public_network_id identifier.

    CLI Example:

    .. code-block:: bash

        salt-cloud -a remove_public_network vm_name public_network_id='123'
    """
    if call != "action":
        raise SaltCloudSystemExit(
            "The remove_public_network action must be called with -a or --action."
        )

    if "public_network_id" not in kwargs:
        log.error("A public_network_id is required.")
        return False

    conn = get_conn()
    node = get_node(conn, name)
    return conn.ex_edit_node_remove_public_network(node, kwargs["public_network_id"])


def create_keypair(kwargs=None, call=None):
    """
    Upload a public key

    name:
        Friendly SSH key name to represent an SSH key.
    default:
        Keys marked as default are always included on server creation and reset unless toggled off in creation/reset request.
    pubkey_path:
        path to public key file

    CLI Example:

    .. code-block:: bash

        salt-cloud -f create_keypair pnap_bmc name='salt' pubkey_path=~/.ssh/id_rsa.pub
    """
    kwargs = _check_required_args(kwargs, call, ["name", "pubkey_path"])
    kwargs.update({"key_material": _get_ssh_keys(kwargs["pubkey_path"])})
    kwargs.update({"default": kwargs.get("default", False)})
    if "pubkey_path" in kwargs:
        del kwargs["pubkey_path"]
    return _create_resource("key_pair", kwargs, call)


def list_keypairs(call=None):
    """
    List all the available SSH keys.

    CLI Example:

    .. code-block:: bash

        salt-cloud -f list_keypairs pnap_bmc
    """
    return _list_resources("key_pair", call)


def show_keypair(kwargs=None, call=None):
    """
    Show the details of an SSH keypair

    name:
        SSH key name.
    CLI Example:

    .. code-block:: bash

        salt-cloud -f show_keypair pnap_bmc name='salt'
    """
    return _show_resource("key_pair", kwargs, call)


def edit_keypair(kwargs=None, call=None):
    """
    Edit an existing SSH key.
    
    name:
        SSH key name.
    new_name:
        New name of the SSH key
    default:
        Keys marked as default are always included on server creation.

    CLI Example:

    .. code-block:: bash

        salt-cloud -f edit_keypair pnap_bmc name='salt' default=True
        salt-cloud -f edit_keypair pnap_bmc name='salt' default=False new_name='saltedit'
    """
    kwargs = _check_required_args(kwargs, call)
    return _edit_resource("key_pair", kwargs, call)


def delete_keypair(kwargs=None, call=None):
    """
    Delete an SSH keypair

    name:
        SSH key name.
    
    CLI Example:

    .. code-block:: bash

        salt-cloud -f delete_keypair pnap_bmc name='salt'
    """
    return _delete_resource("key_pair", kwargs, call)


def create_tag(kwargs=None, call=None):
    """
    Create a tag.

    name:
        The unique name of the tag.
    description:
        The description of the tag.
    is_billing_tag:
        Whether or not to show the tag as part of billing and invoices.
    
    CLI Example:

    .. code-block:: bash

        salt-cloud -f create_tag pnap_bmc name=salt description=test is_billing_tag=False
    """
    kwargs = _check_required_args(kwargs, call)
    kwargs.update({"description": kwargs.get("description", None)})
    kwargs.update({"is_billing_tag": kwargs.get("is_billing_tag", False)})
    return _create_resource("tag", kwargs, call)


def list_tags(call=None):
    """
    List all tags belonging to the BMC Account.

    CLI Example:

    .. code-block:: bash

        salt-cloud -f list_tags pnap_bmc
    """
    return _list_resources("tag", call)


def show_tag(kwargs=None, call=None):
    """
    Show the details of a tag

    name:
        Tag name.
    CLI Example:

    .. code-block:: bash

        salt-cloud -f show_tag pnap_bmc name=salt
    """
    return _show_resource("tag", kwargs, call)


def edit_tag(kwargs=None, call=None):
    """
    Edit an existing tag.

    name:
        Tag name.
    new_name:
        New name of the tag.
    is_blling_tag:
        Whether or not to show the tag as part of billing and invoices.
    description:
        New description of the tag.

    CLI Example:

    .. code-block:: bash

        salt-cloud -f edit_tag pnap_bmc name=salt is_billing_tag=True
        salt-cloud -f edit_tag pnap_bmc name=salt new_name=saltedit
    """
    kwargs = _check_required_args(kwargs, call)
    return _edit_resource("tag", kwargs, call)


def delete_tag(kwargs=None, call=None):
    """
    Delete an existing Tag by name.

    name:
        Tag name.

    CLI Example:

    .. code-block:: bash

        salt-cloud -f delete_tag pnap_bmc name=salt
    """
    return _delete_resource("tag", kwargs, call)


def create_ip_block(kwargs=None, call=None):
    """
    Request an IP Block. An IP Block is a set of contiguous IPs
    that can be assigned to other resources such as servers.

    location:
        IP Block location.
    cidr_block_size:
        CIDR IP Block Size.
    description:
        The description of the IP Block.
    tags:
        Tags to set to ip-block, if any.

    CLI Example:

    .. code-block:: bash

        salt-cloud -f create_ip_block pnap_bmc location=PHX cidr_block_size=/29 description=salt tags='{"name": "salt", "value": "test"}'
    """
    kwargs = _check_required_args(kwargs, call, ["location", "cidr_block_size"])
    kwargs.update({"description": kwargs.get("description", None)})

    if kwargs.get("tags") is not None:
        kwargs["tags"] = _validate_dict_type("tags", kwargs["tags"])
    return _create_resource("ip_block", kwargs, call)


def list_ip_blocks(call=None):
    """
    List all IP Blocks belonging to the BMC Account.

    CLI Example:

    .. code-block:: bash

        salt-cloud -f list_ip_blocks pnap_bmc
    """
    return _list_resources("ip_block", call)


def show_ip_block(kwargs=None, call=None):
    """
    Show the details of a ip_block

    id:
        The IP Block identifier.

    CLI Example:

    .. code-block:: bash

        salt-cloud -f show_ip_block pnap_bmc id=635xxeaa72xx0576axx4dd04
    """
    return _show_resource("ip_block", kwargs, call, based_on="id")


def edit_ip_block(kwargs=None, call=None):
    """
    Update IP Block's details.

    id:
        IP Block identifier.
    description:
        New description of the IP Block.

    CLI Example:

    .. code-block:: bash

        salt-cloud -f edit_ip_block pnap_bmc id=635xxeaa72xx0576axx4dd04 description=saltedit
    """
    kwargs = _check_required_args(kwargs, call, required_args=["id"])
    return _edit_resource("ip_block", kwargs, call, based_on="id")


def edit_ip_block_tags(kwargs=None, call=None):
    """
    Overwrites tags assigned for IP Block and unassigns any tags not part of the request.
    
    id:
        IP Block identifier.
    tags:
        New tags.

    CLI Example:

    .. code-block:: bash

        salt-cloud -f edit_ip_block_tags pnap_bmc id=635xxeaa72xx0576axx4dd04 tags='{"name": "salt", "value": "testedit"}'
    """
    kwargs = _check_required_args(kwargs, call, required_args=["id", "tags"])
    tags = _validate_dict_type("tags", kwargs["tags"])
    ret = get_conn().ex_edit_ip_block_tags_by_id(kwargs["id"], tags=tags)
    return _ip_block_result(ret)


def delete_ip_block(kwargs=None, call=None):
    """
    Delete an IP Block.
    An IP Block can only be deleted if not assigned to any resource.

    id:
        IP Block identifier.
    
    CLI Example:

    .. code-block:: bash

        salt-cloud -f delete_ip_block pnap_bmc id=635xxeaa72xx0576axx4dd04
    """
    return _delete_resource("ip_block", kwargs, call, based_on="id")


def create_private_network(kwargs=None, call=None):
    """
    Create a Private Network.

    name:
        The friendly name of private network.
    location:
        The location of private network.
    cidr:
        IP range associated with this private network in CIDR notation.
    location_default:
        Identifies network as the default private network for the specified location.
    description:
        The description of private network.
    vlan_id:
        The VLAN that will be assigned to this network.
    force:
        Query parameter controlling advanced features availability.
        It is advised to use with caution since it might lead to unhealthy setups.
    
    CLI Example:

    .. code-block:: bash
 
        salt-cloud -f create_private_network pnap_bmc name=salt description=test cidr=10.0.0.0/24 location=PHX
    """
    kwargs = _check_required_args(kwargs, call, ["name", "location"])
    kwargs.update({"description": kwargs.get("description", None)})
    kwargs.update({"location_default": kwargs.get("location_default", False)})
    return _create_resource("private_network", kwargs, call)


def list_private_networks(call=None):
    """
    List all private networks belonging to the BMC Account.

    CLI Example:

    .. code-block:: bash

        salt-cloud -f list_private_networks pnap_bmc
    """
    return _list_resources("private_network", call)


def show_private_network(kwargs=None, call=None):
    """
    Show the details of a private network

    name:
        The name of the Private Network.
    CLI Example:

    .. code-block:: bash

        salt-cloud -f show_private_network pnap_bmc name='salt'
    """
    return _show_resource("private_network", kwargs, call)


def edit_private_network(kwargs=None, call=None):
    """
    Edit an existing private network.

    name:
        The Private Network name you want to edit
    new_name:
        New name of the Private Network
    location_default:
        Identifies network as the default private network for the specified location.
    description:
        New description of Private Network.
    
    CLI Example:

    .. code-block:: bash
 
        salt-cloud -f edit_private_network pnap_bmc name=salt description=edit
        salt-cloud -f edit_private_network pnap_bmc name=salt description=edit location_default=False
    """
    kwargs = _check_required_args(kwargs, call)
    return _edit_resource("private_network", kwargs, call)


def delete_private_network(kwargs=None, call=None):
    """
    Delete an existing private network by name.

    name:
        The Private Network name you want to delete.

    CLI Example:

    .. code-block:: bash

        salt-cloud -f delete_private_network pnap_bmc name=salt
    """
    return _delete_resource("private_network", kwargs, call)


def create_public_network(kwargs=None, call=None):
    """
    Create a Public Network.

    name:
        The friendly name of public network.
    location:
        The location of public network.
    ip_blocks:
        A list of IP Blocks that will be associated with this public network.
    description:
        The description of public network.
    vlan_id:
        The VLAN that will be assigned to this network.
    force:
        Query parameter controlling advanced features availability. 
        It is advised to use with caution since it might lead to unhealthy setups.
    
    CLI Example:

    .. code-block:: bash
 
        salt-cloud -f create_public_network pnap_bmc name=salt description=test location=PHX ip_blocks='[{"id": 636528202a326a32890a5d17}]'
    """
    kwargs = _check_required_args(kwargs, call, ["name", "location"])
    if kwargs.get("ip_blocks") is not None:
        kwargs["ip_blocks"] = _validate_dict_type("ip_blocks", kwargs["ip_blocks"])
    return _create_resource("public_network", kwargs, call)


def list_public_networks(call=None):
    """
    List all public networks belonging to the BMC Account.

    CLI Example:

    .. code-block:: bash

        salt-cloud -f list_public_networks pnap_bmc
    """
    return _list_resources("public_network", call)


def show_public_network(kwargs=None, call=None):
    """
    Show the details of a public network.

    name:
        The name of the Public Network.
    CLI Example:

    .. code-block:: bash

        salt-cloud -f show_public_network pnap_bmc name='salt'
    """
    return _show_resource("public_network", kwargs, call)


def edit_public_network(kwargs=None, call=None):
    """
    Edit an existing public network.

    name:
        The Public Network name you want to edit
    new_name:
        New name of the Public Network
    description:
        New description of Private Network.
    
    CLI Example:

    .. code-block:: bash
 
        salt-cloud -f edit_public_network pnap_bmc name=salt description=edit
        salt-cloud -f edit_public_network pnap_bmc name=salt new_name=saltedit
    """
    kwargs = _check_required_args(kwargs, call)
    return _edit_resource("public_network", kwargs, call)


def edit_public_network_add_ip_block(kwargs=None, call=None):
    """
    Adds an IP block to this public network.

    public_network_id:
        The ID of the Public Network.
    ip_block_id:
        The ID of IP Block

    CLI Example:

    .. code-block:: bash

        salt-cloud -f edit_public_network_add_ip_block pnap_bmc public_network_id=635a8dxx72cdxx76a9e4dxxc ip_block_id=635axxe372xx576a9exxd09
    """
    kwargs = _check_required_args(
        kwargs, call, required_args=["public_network_id", "ip_block_id"]
    )
    ret = get_conn().ex_edit_public_network_add_ip_block(
        kwargs["public_network_id"], kwargs["ip_block_id"]
    )
    return _public_network_result(ret)


def edit_public_network_remove_ip_block(kwargs=None, call=None):
    """
    Removes the IP Block from the Public Network.
    The result of this is that any traffic addressed to any IP within the block will not be routed to this network anymore.
    Please ensure that no resource members within this network have any IPs assigned from the IP Block being removed.
    
    public_network_id:
        The ID of the Public Network.
    ip_block_id:
        The ID of IP Block

    CLI Example:

    .. code-block:: bash

        salt-cloud -f edit_public_network_remove_ip_block pnap_bmc public_network_id=635a8dxx72cdxx76a9e4dxxc ip_block_id=635axxe372xx576a9exxd09
    """
    kwargs = _check_required_args(
        kwargs, call, required_args=["public_network_id", "ip_block_id"]
    )
    ret = get_conn().ex_edit_public_network_remove_ip_block(
        kwargs["public_network_id"], kwargs["ip_block_id"]
    )
    return _public_network_result(ret)


def delete_public_network(kwargs=None, call=None):
    """
    Delete an existing public network by name.

    name:
        The Public Network name you want to delete.

    CLI Example:

    .. code-block:: bash

        salt-cloud -f delete_public_network pnap_bmc name=salt
    """
    return _delete_resource("public_network", kwargs, call)


def create_storage_network(kwargs=None, call=None):
    """
    Create a Storage Network.

    name:
        Storage network friendly name.
    location:
        The location of storage network.
    volumes:
        Volume to be created alongside storage.
    location_default:
        Identifies network as the default private network for the specified location.
    description:
        Storage network description.
    client_vlan:
        Custom Client VLAN that the Storage Network will be set to.
    
    CLI Example:

    .. code-block:: bash
 
        salt-cloud -f create_storage_network pnap_bmc name=salt location=PHX description=test volumes='{"name":"myvolume", "capacityInGb":1000}'
    """
    kwargs = _check_required_args(kwargs, call, ["name", "location", "volumes"])
    kwargs["volumes"] = _validate_dict_type("volumes", kwargs["volumes"])
    kwargs.update({"description": kwargs.get("description", None)})
    return _create_resource("storage_network", kwargs, call)


def list_storage_networks(call=None):
    """
    List all storage networks belonging to the BMC Account.

    CLI Example:

    .. code-block:: bash

        salt-cloud -f list_storage_networks pnap_bmc
    """
    return _list_resources("storage_network", call)


def show_storage_network(kwargs=None, call=None):
    """
    Show the details of a storage network

    name:
        The name of the Storage Network.
    CLI Example:

    .. code-block:: bash

        salt-cloud -f show_storage_network pnap_bmc name='salt'
    """
    return _show_resource("storage_network", kwargs, call)


def edit_storage_network(kwargs=None, call=None):
    """
    Edit an existing storage network.

    name:
        The Storage Network name you want to edit
    new_name:
        New name of the Storage Network
    description:
        New description of Storage Network.
    
    CLI Example:

    .. code-block:: bash
 
        salt-cloud -f edit_storage_network pnap_bmc name=salt new_name=saltedit
    """
    kwargs = _check_required_args(kwargs, call)
    return _edit_resource("storage_network", kwargs, call)


def delete_storage_network(kwargs=None, call=None):
    """
    Delete an existing storage network by name.

    name:
        The Storage Network name you want to delete.

    CLI Example:

    .. code-block:: bash

        salt-cloud -f delete_storage_network pnap_bmc name=salt
    """
    return _delete_resource("storage_network", kwargs, call)


def get_volumes_by_storage_network_id(kwargs=None, call=None):
    """
    Display one or more volumes belonging to a storage network.

    storage_network_id:
        ID of storage network.

    CLI Example:

    .. code-block:: bash

        salt-cloud -f get_volumes_by_storage_network_id pnap_bmc storage_network_id=50dc434c-9bba-427b-bcd6-0bdba45c4dd2
    """
    kwargs = _check_required_args(kwargs, call, required_args=["storage_network_id"])
    ret = get_conn().ex_get_volumes_by_storage_network_id(kwargs["storage_network_id"])
    return ret

def create_volume_in_storage_network(kwargs=None, call=None):
    """
    Create a volume belonging to a storage network.

    storage_network_id:
        ID of storage network.

    volumes:
        Volume to be created.

    CLI Example:

    .. code-block:: bash

        salt-cloud -f create_volume_in_storage_network pnap_bmc storage_network_id=50dc434c-9bba-427b-bcd6-0bdba45c4dd2 volumes='{"name":"myvolume"2, "capacityInGb":1000}'
    """
    kwargs = _check_required_args(kwargs, call, required_args=["storage_network_id", "volumes"])
    if not isinstance(salt.utils.yaml.safe_load(kwargs['volumes']), dict):
        raise SaltCloudConfigError('volumes parameter should be provided as dictionary')
    kwargs["volumes"] = _validate_dict_type("volumes", kwargs["volumes"])[0]
    ret = get_conn().ex_create_volume_in_storage_network(kwargs["storage_network_id"], kwargs["volumes"])
    return ret

def edit_volume_in_storage_network(kwargs=None, call=None):
    """
    Update a storage network's volume details.

    storage_network_id:
        ID of storage network.

    volume_id:
        ID of volume.

    capacity_in_gb: 
        Capacity of Volume in GB.
    
    description: 
        Volume description.

    new_name: 
        New Volume name.

    path_suffix: 
        Last part of volume's path.

    permissions: 
        Update permissions for a volume.

    CLI Example:

    .. code-block:: bash

        salt-cloud -f edit_volume_in_storage_network pnap_bmc storage_network_id=50dc434c-9bba-427b-bcd6-0bdba45c4dd2 volume_id=50dc434c-9bba-427b-bcd6-0bdba45c4dd2 description=edit_desc
    """
    kwargs = _check_required_args(kwargs, call, required_args=["storage_network_id", "volume_id"])
    capacity_in_gb = kwargs.get('capacity_in_gb')
    description = kwargs.get('description')
    new_name = kwargs.get('new_name')
    path_suffix = kwargs.get('path_suffix')
    permissions = kwargs.get('permissions')

    if permissions is not None:
        if not isinstance(salt.utils.yaml.safe_load(permissions), dict):
            raise SaltCloudConfigError('permissions parameter should be provided as dictionary')
        permissions = _validate_dict_type("permissions", permissions)[0]

    ret = get_conn().ex_edit_volume_in_storage_network(kwargs["storage_network_id"], kwargs["volume_id"], capacity_in_gb=capacity_in_gb, description=description, new_name=new_name, path_suffix=path_suffix, permissions=permissions)
    return ret

def edit_volume_tags_in_storage_network(kwargs=None, call=None):
    """
    Overwrites tags assigned for the volume.

    storage_network_id:
        ID of storage network.

    volume_id:
        ID of volume.

    tags: 
        Tags to assign to the volume.

    CLI Example:

    .. code-block:: bash

        salt-cloud -f edit_volume_tags_in_storage_network pnap_bmc storage_network_id=50dc434c-9bba-427b-bcd6-0bdba45c4dd2 volume_id=50dc434c-9bba-427b-bcd6-0bdba45c4dd2 tags=
    """
    kwargs = _check_required_args(kwargs, call, required_args=["storage_network_id", "volume_id", "tags"])
    kwargs["tags"] = _validate_dict_type("tags", kwargs["tags"])
    ret = get_conn().ex_edit_volume_tags_in_storage_network(kwargs["storage_network_id"], kwargs["volume_id"], tags=kwargs['tags'])
    return ret

def delete_volume_in_storage_network(kwargs=None, call=None):
    """
   Delete a Storage Network's Volume

    storage_network_id:
        ID of storage network.

    volume_id:
        ID of volume.

    CLI Example:

    .. code-block:: bash

        salt-cloud -f delete_volume_in_storage_network pnap_bmc storage_network_id=50dc434c-9bba-427b-bcd6-0bdba45c4dd2 volume_id=50dc434c-9bba-427b-bcd6-0bdba45c4dd2
    """
    kwargs = _check_required_args(kwargs, call, required_args=["storage_network_id", "volume_id"])
    ret = get_conn().ex_delete_volume_in_storage_network(kwargs["storage_network_id"], kwargs["volume_id"])
    return ret

def get_product_availability(kwargs=None, call=None):
    """
    Retrieves the list of product availability details.

    product_category:
        The product category.
    product_code:
        The code identifying the product.
    show_only_min_quantity_available:
        Show only locations where product with requested quantity is available or all locations where product is offered.
    location:
        The code identifying the location.
    solution:
        Solutions supported in specific location for a product.
    min_quantity:
        Minimal quantity of product needed.
    
    CLI Example:

    .. code-block:: bash
 
        salt-cloud -f get_product_availability pnap_bmc
        salt-cloud -f get_product_availability pnap_bmc location=PHX
        salt-cloud -f get_product_availability pnap_bmc product_code=s1.c1.medium
    """
    if call != "function":
        raise SaltCloudSystemExit(
            "The  get_product_availability action must be called with -f or --function."
        )

    if not kwargs:
        kwargs = {}

    product_category = kwargs.get("product_category")
    product_code = kwargs.get("product_code")
    show_only_min_quantity_available = kwargs.get("show_only_min_quantity_available")
    min_quantity = kwargs.get("min_quantity")
    location = kwargs.get("location")
    solution = kwargs.get("solution")

    conn = get_conn()
    return conn.ex_get_product_availability(
        product_category=product_category,
        product_code=product_code,
        show_only_min_quantity_available=show_only_min_quantity_available,
        min_quantity=min_quantity,
        location=location,
        solution=solution,
    )


def _keypair_result(response):
    ret = {}
    ret[response.name] = {
        "id": response.extra["id"],
        "default": response.extra["default"],
        "pubkey": response.public_key,
        "fingerprint": response.fingerprint,
        "createdOn": response.extra["createdOn"],
        "lastUpdatedOn": response.extra["lastUpdatedOn"],
    }
    return ret


def _tag_result(response):
    ret = {}
    ret[response.name] = {
        "id": response.id,
        "isBillingTag": response.is_billing_tag,
        "description": response.description,
        "values": response.values,
        "resourceAssignments": response.resource_assignments,
        "createdBy": response.created_by,
    }
    return ret


def _ip_block_result(response):
    ret = {}
    ret[response.id] = {
        "cidr": response.cidr,
        "location": response.location,
        "cidrBlockSize": response.cidr_block_size,
        "description": response.description,
        "status": response.status,
        "assignedResourceId": response.assigned_resource_id,
        "assignedResourceType": response.assigned_resource_type,
        "tags": response.tags,
        "isBringYourOwn": response.is_bring_your_own,
        "createdOn": response.created_on,
    }
    return ret


def _private_network_result(response):
    ret = {}
    ret[response.name] = {
        "id": response.id,
        "location": response.location,
        "vladId": response.vlan_id,
        "description": response.description,
        "privateNetworkType": response.private_network_type,
        "locationDefault": response.location_default,
        "cidr": response.cidr,
        "memberships": response.memberships,
        "createdOn": response.created_on,
    }
    return ret


def _public_network_result(response):
    ret = {}
    ret[response.name] = {
        "id": response.id,
        "location": response.location,
        "vladId": response.vlan_id,
        "description": response.description,
        "memberships": response.memberships,
        "ipBlocks": response.ip_blocks,
        "createdOn": response.created_on,
    }
    return ret


def _storage_network_result(response):
    ret = {}
    ret[response.name] = {
        "id": response.id,
        "location": response.location,
        "status": response.status,
        "description": response.description,
        "networkId": response.network_id,
        "ips": response.ips,
        "createdOn": response.created_on,
        "volumes": response.volumes,
    }
    return ret


def _get_ssh_keys(pubkey_path):
    """
    Read SSH keys from the configuration file
    """
    if pubkey_path is None:
        return None
    ssh_keys_path = os.path.expanduser(pubkey_path)

    if not os.path.isfile(ssh_keys_path):
        raise SaltCloudConfigError(
            "The defined ssh_keys_path '{0}' does not exist".format(ssh_keys_path)
        )

    with salt.utils.files.fopen(ssh_keys_path, "r") as ssh_keys:
        ssh_keys = salt.utils.stringutils.to_unicode(ssh_keys.read())
    return ssh_keys


def _get_cloud_init(cloud_init_path):
    if cloud_init_path is None:
        return None
    cloud_init = os.path.expanduser(cloud_init_path)

    if not os.path.isfile(cloud_init):
        raise SaltCloudConfigError(
            "The defined cloud_init_path '{0}' does not exist".format(cloud_init_path)
        )
    with salt.utils.files.fopen(cloud_init, "r") as ci:
        cloud_init = standard_b64encode(
            salt.utils.stringutils.to_unicode(ci.read()).encode("utf-8")
        ).decode("utf-8")
    return cloud_init


def _create_resource(resource, kwargs, call):
    if call != "function":
        raise SaltCloudSystemExit("This function must be called with -f or --function.")

    conn = get_conn()
    ret = getattr(conn, resource_method[resource]["create"])(**kwargs)
    return resource_method[resource]["result"](ret)


def _edit_resource(resource, kwargs, call, based_on="name"):
    if call != "function":
        raise SaltCloudSystemExit("This function must be called with -f or --function.")

    conn = get_conn()
    target_resource = getattr(conn, resource_method[resource]["show"])(kwargs[based_on])
    if target_resource is None:
        return False
    kwargs[resource] = target_resource

    if "new_name" in kwargs:
        kwargs["name"] = kwargs["new_name"]
        del kwargs["new_name"]
    if resource == "ip_block":
        del kwargs["ip_block"]
    ret = getattr(conn, resource_method[resource]["edit"])(**kwargs)
    return resource_method[resource]["result"](ret)


def _list_resources(resource, call=None):
    if call != "function":
        raise SaltCloudSystemExit("This function must be called with -f or --function.")

    conn = get_conn()
    resources = getattr(conn, resource_method[resource]["list"])()
    ret = {}
    for res in resources:
        ret.update(resource_method[resource]["result"](res))
    return ret


def _show_resource(resource, kwargs=None, call=None, based_on="name"):
    if call != "function":
        raise SaltCloudSystemExit("This function must be called with -f or --function.")

    kwargs = _check_required_args(kwargs, call, [based_on])
    conn = get_conn()
    ret = getattr(conn, resource_method[resource]["show"])(kwargs[based_on])
    return ret and resource_method[resource]["result"](ret)


def _delete_resource(resource, kwargs, call, based_on="name"):
    if call != "function":
        raise SaltCloudSystemExit("This function must be called with -f or --function.")

    kwargs = _check_required_args(kwargs, call, [based_on])
    conn = get_conn()
    res = getattr(conn, resource_method[resource]["show"])(kwargs[based_on])

    if res is None:
        return False
    return getattr(conn, resource_method[resource]["delete"])(res)


def _check_required_args(kwargs, call, required_args=["name"]):
    if call != "function":
        raise SaltCloudSystemExit("This function must be called with -f or --function.")

    if not kwargs:
        kwargs = {}
    for ra in required_args:
        if ra not in kwargs:
            raise SaltCloudConfigError("A '{0}' parameter is required.".format(ra))
    return kwargs


def _validate_dict_type(resource, parameter):
    error_message = (
        "{} parameter should be provided as dictionary or list of dictionaries.".format(
            resource
        )
    )
    parameter_type = salt.utils.yaml.safe_load(parameter)
    if isinstance(parameter_type, list):
        parameter = salt.utils.yaml.safe_load(parameter)
    elif isinstance(parameter_type, dict):
        parameter = [salt.utils.yaml.safe_load(parameter)]
    else:
        raise SaltCloudConfigError(error_message)
   
    for par in parameter:
        if not isinstance(par, dict):
            raise SaltCloudConfigError(error_message)

    return parameter


resource_method = {
    "tag": {
        "create": "ex_create_tag",
        "list": "ex_list_tags",
        "show": "ex_get_tag",
        "edit": "ex_edit_tag",
        "delete": "ex_delete_tag",
        "result": _tag_result,
    },
    "key_pair": {
        "create": "import_key_pair_from_string",
        "list": "list_key_pairs",
        "show": "get_key_pair",
        "edit": "ex_edit_key_pair",
        "delete": "delete_key_pair",
        "result": _keypair_result,
    },
    "ip_block": {
        "create": "ex_create_ip_block",
        "list": "ex_list_ip_blocks",
        "show": "ex_get_ip_block_by_id",
        "edit": "ex_edit_ip_block_by_id",
        "delete": "ex_delete_ip_block_by_id",
        "result": _ip_block_result,
    },
    "private_network": {
        "create": "ex_create_private_network",
        "list": "ex_list_private_networks",
        "show": "ex_get_private_network",
        "edit": "ex_edit_private_network",
        "delete": "ex_delete_private_network",
        "result": _private_network_result,
    },
    "public_network": {
        "create": "ex_create_public_network",
        "list": "ex_list_public_networks",
        "show": "ex_get_public_network",
        "edit": "ex_edit_public_network",
        "delete": "ex_delete_public_network",
        "result": _public_network_result,
    },
    "storage_network": {
        "create": "ex_create_storage_network",
        "list": "ex_list_storage_networks",
        "show": "ex_get_storage_network",
        "edit": "ex_edit_storage_network",
        "delete": "ex_delete_storage_network",
        "result": _storage_network_result,
    },
}
