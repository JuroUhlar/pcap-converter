const fs = require('fs-extra');
const Axios = require('axios');
const ProgressBar = require('progress')

async function downloadFile(fileUrl, outputLocationPath) {
  const writer = fs.createWriteStream(outputLocationPath);

  return Axios({
    method: 'get',
    url: fileUrl,
    responseType: 'stream',
    onDownloadProgress(progress) {
      console.log('download progress:', progress);
    }
  }).then(response => {
    const totalLength = response.headers['content-length'];
    console.log(totalLength);

    const progressBar = new ProgressBar('-> downloading [:bar] :percent :etas', {
      width: 40,
      complete: '=',
      incomplete: ' ',
      renderThrottle: 1,
      total: parseInt(totalLength)
    })

    response.data.on('data', (chunk) => progressBar.tick(chunk.length))

    //ensure that the user can call `then()` only when the file has
    //been downloaded entirely.

    return new Promise((resolve, reject) => {
      response.data.pipe(writer);
      let error = null;
      writer.on('error', err => {
        error = err;
        writer.close();
        reject(err);
      });
      writer.on('close', () => {
        if (!error) {
          resolve(true);
        }
        //no need to call the reject here, as it will have been called in the
        //'error' stream;
      });
    });
  });
}

//   downloadFile('https://s3.amazonaws.com/tcpreplay-pcap-files/test.pcap', './public/test1.pcap').then(console.log('done'));

function getFileNameFromURL(url) {
  let parts = url.split('/');
  let file = parts[parts.length - 1];
  let name = file.split('.')[0];
  return name;
}

module.exports = {
  downloadFile,
  getFileNameFromURL
};