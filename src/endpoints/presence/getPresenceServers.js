import xml from 'xml';

function createPresenceServersXML() {
    // The native client commits the ROS credentials only after this endpoint
    // succeeds. A missing relay configuration must not turn sign-in into a 500,
    // so fall back to the configured public hostname and the conventional port.
    const relayAddress = process.env.RELAY_PUBLIC_ADDRESS || process.env.ROS_HOST || process.env.DOMAIN;
    const relayPort = process.env.RELAY_PUBLIC_PORT || '61456';

    const servers = [
        { host: `${relayAddress}:${relayPort}` },
    ];

    // Create server entries for XML structure
    const serverEntries = servers.map(server => ({
        Server: [{ _attr: { Host: server.host, IsSecure: 'false', IsXblSg: 'false' } }]
    }));

    const xmlStructure = [
        {
            Response: [
                {
                    _attr: {
                        'xmlns:xsd': 'http://www.w3.org/2001/XMLSchema',
                        'xmlns:xsi': 'http://www.w3.org/2001/XMLSchema-instance',
                        xmlns: 'GetPresenceServersResponse',
                    },
                },
                { Status: '1' },
                {
                    Result: [
                        { _attr: { Count: servers.length.toString(), IsSecure: 'false', IsXblSg: 'false' } },
                        ...serverEntries
                    ],
                },
            ],
        },
    ];

    return xml(xmlStructure, { declaration: true });
}

export const getPresenceServersHandler = (req, res) => {
    res.set('Content-Type', 'text/xml');
    console.log(createPresenceServersXML());
    res.send(createPresenceServersXML());
};
