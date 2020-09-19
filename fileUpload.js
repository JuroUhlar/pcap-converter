const express = require('express');
const fileUpload = require('express-fileupload');
const cors = require('cors');
const bodyParser = require('body-parser');
const morgan = require('morgan');
const _ = require('lodash');
const { exec } = require("child_process");
const fs = require('fs');
const fsExtra = require('fs-extra')
const { pcapCSVToDatasetJson } = require('./parse')

const app = express();

// enable files upload
app.use(fileUpload({
    createParentPath: true
}));

//add other middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(morgan('dev'));

//start app 
const port = process.env.PORT || 5000;

app.listen(port, () =>
    console.log(`App is listening on port ${port}.`)
);

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
            fsExtra.emptyDirSync(slicedFolder);
        }
        let sliceCommnad = `editcap -c 3000 ./progressive/${name}/${pcap.name} ./progressive/${name}/sliced/${pcap.name} `;
        console.log(sliceCommnad);

        exec(sliceCommnad, (error, stdout, stderr) => {
            if (error) {
                console.log(`error: ${error.message}`);
                return;
            }
            if (stderr) console.log(`${stderr}`);
            if (stdout) console.log(stdout);

            const files = fs.readdirSync(slicedFolder);
            // console.log(files);
            // files.forEach(file => {
            //     console.log(file);
            // });
            convertPcapsRecursively(files, 0, slicedFolder);
        });

        res.send({
            status: true,
            message: 'File is uploaded',
            data: {
                name: pcap.name,
                mimetype: pcap.mimetype,
                size: pcap.size,
                extractedDataset: []
            }
        });
    } catch (err) {
        res.status(500).send(err);
    }
});


function convertPcapsRecursively(pcaps, index, folder) {
    if (index >= pcaps.length) return;
    let pcap = pcaps[index];
    console.log('\n' + pcap);

    let name = pcap.split('.')[0];
    let inputFile = `${folder}/${pcap}`;
    let outputCSVFile = `${folder}/${name}.csv`;
    let tshark = tsharkCommand(inputFile, outputCSVFile);
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
        convertPcapsRecursively(pcaps, index + 1, folder);
    });

}

function tsharkCommand(inputFile, outputCSVFile) {
    return `tshark -r ${inputFile} -T fields -E separator=, -E header=y -E occurrence=f -e frame.number -e ip.src -e ip.dst -e ipv6.src -e ipv6.dst -e arp.src.proto_ipv4 -e arp.dst.proto_ipv4 -e frame.time_epoch -e frame.protocols -e udp.srcport -e udp.dstport -e tcp.srcport -e tcp.dstport -e frame.len > ${outputCSVFile}`;
}