const fs = require('fs');
var tools = require('./portAppData');

// let pcapFiles = fs.readdirSync("./pcap");
// console.log("Pcap files found: ", pcapFiles);

// var n = pcapFiles.length;
// var counter = 0;

// pcapFiles.forEach((file, index) => {
//     let name = file.split('.')[0];

//     let inputFile = `./pcap/${file}`;
//     let outputFile = `./csv/${name}.csv`;
//     let tshark = `tshark -r ${inputFile} -T fields -E separator=, -E header=y -E occurrence=f -e frame.number -e ip.src -e ip.dst -e ipv6.src -e ipv6.dst -e arp.src.proto_ipv4 -e arp.dst.proto_ipv4 -e frame.time_epoch -e frame.protocols -e udp.srcport -e udp.dstport -e tcp.srcport -e tcp.dstport -e frame.len > ${outputFile}`

//     const { exec } = require("child_process");

//     exec(tshark, (error, stdout, stderr) => {
//         if (error) {
//             console.log(`error: ${error.message}`);
//             return;
//         }
//         if (stderr) {
//             console.log(`stderr: ${stderr}`);
//             return;
//         }
//         // console.log(`stdout: ${stdout}`);
//         let t0 = new Date();
//         counter += 1;
//         pcapCSVToDatasetJson(outputFile, `./csv/${name}.json`)
//         let t1 = new Date();
//         console.log(`Process ${index + 1} - "${name}" finished. (${counter}/${n} done)`);
//         console.log('Execution time: %dms', t1 - t0);
//     });
// });


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
    // console.log(sourceApp, destinationApp);
    if (sourceApp && !destinationApp) return sourceApp;
    if (!sourceApp && destinationApp) return destinationApp;
    if (sourceApp && destinationApp && sourceApp === destinationApp) return sourceApp;
    if (sourceApp && destinationApp) {
        // console.log('conflict', sourceApp, destinationApp);
        if (sourcePort < destinationPort) return sourceApp;
        else return destinationApp;
    };
    // console.log('null', sourcePort, destinationPort);
    return null;
}

function parse_pcap_csvFile(path) {
    // console.log(path);
    const fs = require('fs');
    const parse = require('csv-parse/lib/sync')

    var csv = fs.readFileSync(path, 'utf8');
    // console.log(csv);
    // const parse = require('csv-parse/lib/sync')

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
    pcapCSVToDatasetJson 
};
