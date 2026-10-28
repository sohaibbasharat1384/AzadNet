"""Private stdin JSON -> NetworkManager; only app-owned volatile IKEv2 profiles."""
import json
import re
import sys
import time
import uuid


def main(request):
    import dbus
    bus = dbus.SystemBus()
    service = 'org.freedesktop.NetworkManager'
    props = 'org.freedesktop.DBus.Properties'
    root = '/org/freedesktop/NetworkManager'
    manager = dbus.Interface(bus.get_object(service, root), service)
    properties = dbus.Interface(bus.get_object(service, root), props)
    operation = request['operation']
    name = request['name']
    identity = request.get('uuid', '')
    if not re.fullmatch(r'AzadNet-Windscribe-[a-f0-9]{32}', name):
        raise ValueError('invalid_owner')
    if operation == 'available':
        return {'available': True}
    if str(uuid.UUID(identity)) != identity:
        raise ValueError('invalid_uuid')
    def own_connections():
        result = []
        for path in properties.Get(service, 'ActiveConnections'):
            p = dbus.Interface(bus.get_object(service, path), props)
            values = p.GetAll(service + '.Connection.Active')
            if str(values.get('Id')) == name and str(values.get('Uuid')) == identity:
                result.append((path, values))
        return result
    if operation == 'status':
        return {'connected': any(int(v['State']) == 2 for _, v in own_connections())}
    if operation == 'stop':
        for path, _ in own_connections():
            manager.DeactivateConnection(path)
        for _ in range(40):
            if not own_connections():
                break
            time.sleep(0.25)
        if own_connections():
            return {'error': 'ikev2_disconnect_failed'}
        settings = dbus.Interface(bus.get_object(service, root + '/Settings'), service + '.Settings')
        for path in settings.ListConnections():
            connection = dbus.Interface(bus.get_object(service, path), service + '.Settings.Connection')
            data = connection.GetSettings().get('connection', {})
            if str(data.get('id')) == name and str(data.get('uuid')) == identity:
                connection.Delete()
        return {'stopped': True}
    if operation != 'connect':
        raise ValueError('unknown_operation')
    host = request['server']
    user = request['username']
    password = request['password']
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}', host):
        raise ValueError('invalid_server')
    if any(not isinstance(v, str) or not v or len(v) > 256 or re.search(r'[\x00-\x1f\x7f]', v) for v in (user, password)):
        raise ValueError('invalid_credentials')
    values = {'address': host, 'method': 'eap', 'user': user, 'virtual': 'yes', 'encap': 'yes', 'ipcomp': 'no', 'password-flags': '0'}
    # System trust validates the server's DNS identity. No root CA is installed.
    data = dbus.Dictionary({
        'connection': dbus.Dictionary({'id': name, 'uuid': identity, 'type': 'vpn', 'autoconnect': dbus.Boolean(False)}, signature='sv'),
        'vpn': dbus.Dictionary({'service-type': service + '.strongswan', 'data': dbus.Dictionary(values, signature='ss'), 'secrets': dbus.Dictionary({'password': password}, signature='ss')}, signature='sv'),
        'ipv4': dbus.Dictionary({'method': 'auto', 'never-default': dbus.Boolean(False), 'route-metric': dbus.UInt32(50)}, signature='sv'),
        'ipv6': dbus.Dictionary({'method': 'auto', 'never-default': dbus.Boolean(False), 'route-metric': dbus.UInt32(50)}, signature='sv'),
    }, signature='sa{sv}')
    connection_path, active_path, _ = manager.AddAndActivateConnection2(data, dbus.ObjectPath('/'), dbus.ObjectPath('/'), dbus.Dictionary({'persist': 'volatile'}, signature='sv'))
    active = dbus.Interface(bus.get_object(service, active_path), props)
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        state = int(active.Get(service + '.Connection.Active', 'State'))
        if state == 2:
            return {'connected': True}
        if state == 4:
            break
        time.sleep(0.25)
    manager.DeactivateConnection(active_path)
    return {'error': 'ikev2_connect_failed'}


if __name__ == '__main__':
    try:
        raw = sys.stdin.read(32769)
        if len(raw) > 32768:
            raise ValueError('oversized_request')
        print(json.dumps(main(json.loads(raw))))
    except Exception as error:
        # Exception messages may contain credentials, so only return the class.
        print(json.dumps({'error': 'ikev2_system_operation_failed', 'kind': type(error).__name__}))
