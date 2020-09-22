const express = require('express');
const fileUpload = require('express-fileupload');
const cors = require('cors');
const bodyParser = require('body-parser');
const morgan = require('morgan');
const compression = require('compression');
const { exec } = require("child_process");
const fs = require('fs-extra');
const { pcapCSVToDatasetJson } = require('./parse');
const socketIO = require('socket.io');
const siofu = require("socketio-file-upload");

const app = express();

app.use(fileUpload({
    createParentPath: true
}));
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(morgan('dev'));
app.use(compression());
app.use(siofu.router)

//start app 
const port = process.env.PORT || 5000;
var server = app.listen(port, () =>
    console.log(`App is listening on port ${port}.`)
);


// Sockets
var io = socketIO(server);

io.on('connection', (socket) => {
    console.log('a user connected');

    // File uplaoding
    var uploader = new siofu();
    uploader.dir = "./progressive";
    uploader.listen(socket);

    // Do something when a file is saved:
    uploader.on("saved", function (event) {
        console.log("File successfully uplaoded: " + event.file.name);

        let pcap = event.file;
        let name = pcap.name.split('.')[0];
        const slicedFolder = `./progressive/${name}`;
        fs.ensureDirSync(slicedFolder)
        fs.emptyDirSync(slicedFolder);
        let sliceCommnad = `editcap -c 10000 ./progressive/${pcap.name} ${slicedFolder}/${pcap.name} `;
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
            socket.emit('batch', files);
            convertPcapsRecursivelySocket(files, 0, slicedFolder, socket);
        });
    });

    // Error handler:
    uploader.on("error", function (event) {
        console.log("Error from uploader", event);
    });

    socket.on('disconnect', () => {
        console.log('user disconnected');
    });

    // socket.on('file', (data) => {
    //     console.log(data);
    //     let counter = 1;
    //     let interval = setInterval(() => {
    //         socket.emit('batch', `Batch ${counter} out of 10`);
    //         counter++;
    //         if (counter === 11) clearInterval(interval);
    //     }, 1000)
    // });
});








app.get('/', (req, res) => {
    res.send('Hello World! The pcap converter should be running')
})


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
        console.log('\n\n' + pcap.name);
        let t0 = new Date();

        //Use the name of the input field (i.e. "avatar") to retrieve the uploaded file

        //Use the mv() method to place the file in upload directory (i.e. "uploads")
        pcap.mv('./uploads/' + pcap.name);

        let name = pcap.name.split('.')[0];
        let inputFile = `./uploads/${pcap.name}`;
        let outputCSVFile = `./csv/${name}.csv`;
        let tshark = `tshark -r ${inputFile} -T fields -E separator=, -E header=y -E occurrence=f -e frame.number -e ip.src -e ip.dst -e ipv6.src -e ipv6.dst -e arp.src.proto_ipv4 -e arp.dst.proto_ipv4 -e frame.time_epoch -e frame.protocols -e udp.srcport -e udp.dstport -e tcp.srcport -e tcp.dstport -e frame.len > ${outputCSVFile}`

        console.log(tshark);

        exec(tshark, (error, stdout, stderr) => {
            if (error) {
                console.log(`error: ${error.message}`);
                return;
            }
            if (stderr) {
                console.log(`stderr: ${stderr}`);
                return;
            }
            let t1 = new Date();
            console.log('Parsed by Tshark in: %dms', t1 - t0);

            pcapCSVToDatasetJson(outputCSVFile, `./datasets/${name}.json`);
            var datasetFile = fs.readFileSync(`./datasets/${name}.json`);
            let packets = JSON.parse(datasetFile);
            //send response
            res.send({
                status: true,
                message: 'File is uploaded',
                data: {
                    name: pcap.name,
                    mimetype: pcap.mimetype,
                    size: pcap.size,
                    extractedDataset: packets.slice(0, 100000)
                }
            });

            let t2 = new Date();
            console.log('Converted to dataset in: %dms', t2 - t1);

        });
    } catch (err) {
        res.status(500).send(err);
    }
});

app.post('/convert-progressive', async (req, res) => {
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
        console.log('\n\n' + pcap.name);
        const slicedFolder = `./progressive/${name}/sliced`;


        //Use the mv() method to place the file in upload directory (i.e. "uploads")
        pcap.mv(`./progressive/${name}/` + pcap.name);
        if (!fs.existsSync(slicedFolder)) {
            fs.mkdirSync(slicedFolder);
        } else {
            fs.emptyDirSync(slicedFolder);
        }
        let sliceCommnad = `editcap -c 10000 ./progressive/${name}/${pcap.name} ./progressive/${name}/sliced/${pcap.name} `;
        console.log(sliceCommnad);

        exec(sliceCommnad, (error, stdout, stderr) => {
            if (error) {
                console.log(`error: ${error.message}`);
                return;
            }
            if (stderr) console.log(`${stderr}`);
            if (stdout) console.log(stdout);

            const files = fs.readdirSync(slicedFolder);
            convertPcapsRecursively(files, 0, slicedFolder, res);

        });
    } catch (err) {
        res.status(500).send(err);
    }
});

function convertPcapsRecursively(pcaps, index, folder, res) {
    if (index >= pcaps.length) {
        console.log('All done');
        return;
    }
    let pcap = pcaps[index];
    console.log('\n' + pcap);

    let name = pcap.split('.')[0];
    let inputFilePath = `${folder}/${pcap}`;
    let outputCSVFilePath = `${folder}/${name}.csv`;
    let outputJSONFilePath = `${folder}/${name}.json`;
    let tshark = tsharkCommand(inputFilePath, outputCSVFilePath);
    console.log(tshark);
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

        if (index === 0) {
            console.log("Sending packets back");
            var datasetFile = fs.readFileSync(outputJSONFilePath);
            let packets = JSON.parse(datasetFile);
            res.send({
                status: true,
                message: 'File is uploaded',
                data: {
                    name: pcap,
                    extractedDataset: packets.slice(0, 10000)
                }
            });
        };

        deleteFile(inputFilePath);
        deleteFile(outputCSVFilePath);
        convertPcapsRecursively(pcaps, index + 1, folder);
    });
}

function convertPcapsRecursivelySocket(pcaps, index, folder, socket) {
    if (index >= pcaps.length) {
        console.log('All done');
        return;
    }
    let pcap = pcaps[index];
    console.log('\n' + pcap);

    let name = pcap.split('.')[0];
    let inputFilePath = `${folder}/${pcap}`;
    let outputCSVFilePath = `${folder}/${name}.csv`;
    let outputJSONFilePath = `${folder}/${name}.json`;
    let tshark = tsharkCommand(inputFilePath, outputCSVFilePath);
    console.log(tshark);
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
        socket.emit('batch', {
            batch: index,
            data: {
                extractedDataset: packets.slice(0, 10000)
            }
        });


        deleteFile(inputFilePath);
        deleteFile(outputCSVFilePath);
        convertPcapsRecursivelySocket(pcaps, index + 1, folder, socket);
    });
}

function tsharkCommand(inputFilePath, outputCSVFile) {
    return `tshark -r ${inputFilePath} -T fields -E separator=, -E header=y -E occurrence=f -e frame.number -e ip.src -e ip.dst -e ipv6.src -e ipv6.dst -e arp.src.proto_ipv4 -e arp.dst.proto_ipv4 -e frame.time_epoch -e frame.protocols -e udp.srcport -e udp.dstport -e tcp.srcport -e tcp.dstport -e frame.len > ${outputCSVFile}`;
}

function deleteFile(path) {
    fs.unlink(path, (err) => {
        if (err) {
            console.error(err)
            return
        };
    })
}