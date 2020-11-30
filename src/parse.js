const fs = require('fs');
var tools = require('./portAppData');

function parsedCsvToDataset(data) {
    dataset = [];
    data.forEach(packet => {
        let protocols = packet["frame.protocols"].split(':');
        let networkProtocol = protocols[2];
        let transportProtocol = protocols[3];
        let applicationProtocol = protocols[4];

        let sourceIp = '';
        let destinationIp = ''
        if (networkProtocol == "ip") {
            sourceIp = packet["ip.src"]
            destinationIp = packet["ip.dst"]
        }
        if (networkProtocol == "arp") {
            sourceIp = packet["arp.src.proto_ipv4"]
            destinationIp = packet["arp.dst.proto_ipv4"]
        }
        if (networkProtocol == "ipv6") {
            sourceIp = packet["ipv6.src"]
            destinationIp = packet["ipv6.dst"]
        }

        let sourcePort = 0
        let destinationPort = 0

        if (transportProtocol == 'tcp') {
            sourcePort = +packet["tcp.srcport"]
            destinationPort = +packet["tcp.dstport"]
        }
        if (transportProtocol == 'udp') {
            sourcePort = +packet["udp.srcport"]
            destinationPort = +packet["udp.dstport"]
        }
        if (transportProtocol == 'icmp') {
            if (protocols[5] == 'udp') {
                sourcePort = +packet["udp.srcport"]
                destinationPort = +packet["udp.dstport"]
            }
        }

        let extractedPacket = {
            index: +packet['frame.number'],
            timestamp: +packet["frame.time_epoch"],
            networkProtocol: networkProtocol,
            transportProtocol: transportProtocol,
            applicationProtocol: applicationProtocol,
            sourceIp: sourceIp,
            destinationIp: destinationIp,
            sourcePort: +sourcePort,
            destinationPort: +destinationPort,
            bytes: +packet["frame.len"],
            app: getApp(+sourcePort, +destinationPort) ? getApp(+sourcePort, +destinationPort) : undefined,
        }

        dataset.push(extractedPacket)
    });
    return dataset;
}

const getApp = (sourcePort, destinationPort) => {
    let sourceApp = tools.getPortService(sourcePort);
    let destinationApp = tools.getPortService(destinationPort);
    if (sourceApp && !destinationApp) return sourceApp;
    if (!sourceApp && destinationApp) return destinationApp;
    if (sourceApp && destinationApp && sourceApp === destinationApp) return sourceApp;
    if (sourceApp && destinationApp) {
        if (sourcePort < destinationPort) return sourceApp;
        else return destinationApp;
    };
    return null;
}

function parse_pcap_csvFile(path) {
    const fs = require('fs');
    const parse = require('csv-parse/lib/sync')
    var csv = fs.readFileSync(path, 'utf8');

    const jsonData = parse(csv, {
        columns: true,
        skip_empty_lines: true
    })
    return parsedCsvToDataset(jsonData);
}

function pcapCSVToDatasetJson(csvPath, outputFileName) {
    let dataset = parse_pcap_csvFile(csvPath);
    storeData(dataset, outputFileName)
}

function storeData(data, path) {
    const fs = require('fs')
    try {
        fs.writeFileSync(path, JSON.stringify(data))
    } catch (err) {
        console.error(err)
    }
}

module.exports = {
    pcapCSVToDatasetJson,
    storeData,
};
