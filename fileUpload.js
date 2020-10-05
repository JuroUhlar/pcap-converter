const express = require('express');
const fileUpload = require('express-fileupload');
const cors = require('cors');
const bodyParser = require('body-parser');
const morgan = require('morgan');
const compression = require('compression');
const { exec } = require("child_process");
const fs = require('fs-extra');
const { pcapCSVToDatasetJson, storeData } = require('./parse');
const socketIO = require('socket.io');
const { downloadFile, getFileNameFromURL } = require("./downloadFile");

const app = express();

app.use(fileUpload({
    createParentPath: true
}));
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(morgan('dev'));
app.use(compression());
app.use(express.static('public'))

const port = process.env.PORT || 5000;

//start app 
var server = app.listen(port, () =>
    console.log(`App is listening on port ${port}.`)
);

app.get('/', (req, res) => {
    res.send('The pcap converter server is running.')
})

app.get('/list-saved', (req, res) => {
    let files = fs.readdirSync('./public/datasets');
    files = files.filter(file => file !== '.gitignore');
    console.log(files);
    res.send(files);
})

app.get('/get-pcap-from-url', (req, res) => {
    try {
        let url = req.query.url;
        let name = getFileNameFromURL(url);
        let filePath = `./progressive/${name}.pcap`;
        while (fs.existsSync(filePath) || fs.existsSync(`./progressive/${name}`)) {
            name += '_01';
            filePath = `./progressive/${name}.pcap`;
        }
        console.log(`\n Downloading file from ${url}`);
        downloadFile(url, filePath)
            .then(() => {
                console.log('File downloaded to ', filePath)
                res.send(filePath);
            })
            .catch(err => {
                console.log(err)
                res.status(500).send(err);
            });
    } catch (err) {
        console.log(err)
        res.status(500).send('Internal server error: ', err);
    }
})


// Upload pcap file
app.post('/upload-pcap', async (req, res) => {
    try {
        if (!req.files) {
            res.send({
                status: false,
                message: 'No file uploaded'
            });
            return;
        }
        let pcap = req.files.pcap;
        let name = pcap.name.split('.')[0];
        let filePath = `./progressive/${pcap.name}`;
        while (fs.existsSync(filePath) || fs.existsSync(`./progressive/${name}`)) {
            name += '_01';
            filePath = `./progressive/${name}.pcap`;
        }
        pcap.mv(filePath);
        res.send({
            status: true,
            message: 'File is uploaded',
            filePath,
            name,
        });

    } catch (err) {
        res.status(500).send(err);
    }
});


// Sockets
var io = socketIO(server);

io.on('connection', (socket) => {
    console.log('a user connected');

    socket.on('requestDataset', (data) => {
        console.log(data);
        const name = data.name;
        const pcapFilePath = data.filePath;

        const slicedFolder = `./progressive/${name}`;
        fs.ensureDirSync(slicedFolder);
        let sliceCommnad = `editcap -c 10000 ${pcapFilePath} ${slicedFolder}/${name + '.pcap'}`;
        console.log(sliceCommnad);

        exec(sliceCommnad, (error, stdout, stderr) => {
            if (error) {
                console.log(`error: ${error.message}`);
                return;
            }
            if (stderr) console.log(`${stderr}`);
            if (stdout) console.log(stdout);

            const files = fs.readdirSync(slicedFolder);
            console.log(files);

            var allPackets = [];

            convertPcapsRecursivelySocket(files, 0, slicedFolder, socket, allPackets, name);
            deleteFile(pcapFilePath);
        });
    });

    socket.on('submitPcapUrl', (data) => {
        const url = data.url;
        console.log('Download file from', url);
    })

    socket.on('disconnect', () => {
        console.log('user disconnected');
    });
});

function convertPcapsRecursivelySocket(pcaps, index, folder, socket, allPackets, originalName) {
    if (index >= pcaps.length) {
        deleteFile(folder);
        console.log('All done');
        storeData(allPackets, `./public/datasets/${originalName}.json`)
        return;
    }

    let pcap = pcaps[index];
    console.log('\n' + pcap);

    let name = pcap.split('.')[0];
    let inputFilePath = `${folder}/${pcap}`;
    let outputCSVFilePath = `${folder}/${name}.csv`;
    let outputJSONFilePath = `${folder}/${name}.json`;
    let tshark = tsharkCommand(inputFilePath, outputCSVFilePath);
    // console.log(tshark);
    exec(tshark, (error, stdout, stderr) => {
        if (error) {
            console.log(`error: ${error.message}`);
            return;
        }
        if (stderr) {
            console.log(`stderr: ${stderr}`);
            return;
        }
        console.log('Parsed by Tshark.');
        pcapCSVToDatasetJson(outputCSVFilePath, outputJSONFilePath);

        console.log("Sending packets back");
        var datasetFile = fs.readFileSync(outputJSONFilePath);
        let packets = JSON.parse(datasetFile);

        allPackets = allPackets.concat(packets);

        let message = index === 0 ? 'newDataset' : 'batch';
        let lastBatch = index + 1 === pcaps.length
        socket.emit(message, {
            batch: `${index + 1} / ${pcaps.length}`,
            lastBatch,
            data: {
                extractedDataset: packets.slice(0, 10000)
            }
        });

        deleteFile(inputFilePath);
        deleteFile(outputCSVFilePath);
        convertPcapsRecursivelySocket(pcaps, index + 1, folder, socket, allPackets, originalName);
    });
}

function tsharkCommand(inputFilePath, outputCSVFile) {
    return `tshark -r ${inputFilePath} -T fields -E separator=, -E header=y -E occurrence=f -e frame.number -e ip.src -e ip.dst -e ipv6.src -e ipv6.dst -e arp.src.proto_ipv4 -e arp.dst.proto_ipv4 -e frame.time_epoch -e frame.protocols -e udp.srcport -e udp.dstport -e tcp.srcport -e tcp.dstport -e frame.len > ${outputCSVFile}`;
}

function deleteFile(path) {
    fs.remove(path, (err) => {
        if (err) {
            console.error(err)
            return
        };
    })
}