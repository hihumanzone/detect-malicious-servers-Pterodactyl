const fs = require('fs');
const axios = require('axios');
const path = require('path');

const API_KEY = '';
const API_KEY_FILES = '';
const BASE_URL = '';
const GROQ_API_KEY = '';
const MODEL = 'llama-3.1-70b-versatile';
const MAX_RETRIES = 3;
const system_prompt = `Please rate the following code out of 10 for malicious intent on a Discord bot hosting site. Your response should be in JSON format, as it will be used by an automated system to deactivate malicious code and auto-suspend their respective servers. The \`data.rating\` should be a number from 1 to 10, and \`data.description\` should provide a short explanation for the rating.

Consider the following:
- Ignore any sensitive information, such as API keys and bot tokens.
- Assume the code is for personal use only; ignore security risks, major bugs, complexity, file handling, integrations with known APIs and services, extensive functionality, or poorly written code.
- Encrypted code is highly suspicious.
- Be honest and thorough, as your rating will determine whether the server associated with this code should be suspended.

Directly provide the JSON response without any further explanation or use of any natural language to describe it, or anything else. Don't even use a code block to cover the JSON code.

Example JSON output:
{
  "data": {
    "description": "No malicious intent detected in the provided code. The code appears to be a Discord bot designed for text and image generation, with various features and settings. It does not contain any obvious backdoors or malicious code.",
    "rating": 0
  }
}`;

async function deactai(string) {
  const url = 'https://api.groq.com/openai/v1/chat/completions';
  const headers = {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${GROQ_API_KEY}`,
  };
  const data = {
    model: MODEL,
    messages: [
      {
        role: 'system',
        content: system_prompt,
      },
      {
        role: 'user',
        content: string,
      },
    ],
  };

  let attempts = 0;
  while (attempts < MAX_RETRIES) {
    try {
      const response = await axios.post(url, data, { headers });
      return JSON.parse(response.data.choices?.[0]?.message?.content);
    } catch (error) {
      attempts += 1;
      console.error(`Detection attempt ${attempts} failed:`, error.message);
      if (attempts === MAX_RETRIES) {
        return {
          data: {
            rating: false,
            description: false,
          }
        };
      }
    }
  }
}

function logInfo(message) {
  console.log(message);
  fs.appendFileSync('info.log', `${new Date().toISOString()} - INFO: ${message}\n`);
}

function logError(message) {
  console.error(message);
  fs.appendFileSync('error.log', `${new Date().toISOString()} - ERROR: ${message}\n`);
}

async function fetchServers() {
  const HEADERS = {
    'Accept': 'application/json',
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${API_KEY}`
  };
  try {
    const response = await axios.get(`${BASE_URL}/application/servers`, { headers: HEADERS });
    return response.data.data;
  } catch (error) {
    logError('Error fetching servers:', error.message);
    throw error;
  }
}

async function fetchFileList(serverIdentifier, directory = '/') {
  const HEADERS = {
    'Accept': 'application/json',
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${API_KEY_FILES}`
  };
  try {
    const response = await axios.get(`${BASE_URL}/client/servers/${serverIdentifier}/files/list${`?directory=${encodeURIComponent(directory)}`}`, { headers: HEADERS });
    return response.data.data;
  } catch (error) {
    logError(`Error fetching file list for server ${serverIdentifier}: ${error.message}`);
    throw error;
  }
}

async function fetchFileContent(serverIdentifier, filePath) {
  const HEADERS = {
    'Accept': 'application/json',
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${API_KEY_FILES}`
  };
  try {
    const response = await axios.get(`${BASE_URL}/client/servers/${serverIdentifier}/files/contents?file=${encodeURIComponent(filePath)}`, { headers: HEADERS });
    return response.data;
  } catch (error) {
    logError(`Error fetching file content for server ${serverIdentifier}, file ${filePath}: ${error.message}`);
    throw error;
  }
}

async function traverseFiles(serverIdentifier, directory = '/', fileExtensions = ['.js', '.py', '.ts', '.cs', '.rs', '.lua']) {
  try {
    const fileList = await fetchFileList(serverIdentifier, directory);
    let files = [];

    for (const file of fileList) {
      const fileName = file.attributes.name;

      if (fileName === 'node_modules' || fileName === '.npm') {
        continue;
      }

      if (file.attributes.is_file) {
        if (fileExtensions.includes(path.extname(fileName))) {
          files.push(`${directory}/${fileName}`);
        }
      } else {
        files = files.concat(await traverseFiles(serverIdentifier, `${directory}/${fileName}`, fileExtensions));
      }
    }
    return files;
  } catch (error) {
    logError(`Error traversing files for server ${serverIdentifier}: ${error.message}`);
    throw error;
  }
}

async function main() {
  const HEADERS = {
    'Accept': 'application/json',
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${API_KEY}`
  };
  try {
    const startTime = Date.now();
    const servers = await fetchServers();
    const unsuspendedServers = servers.filter(server => !server.attributes.suspended);

    let scanned = 0;
    let suspicious = 0;
    let suspended = 0;
    const suspiciousServers = [];
    const suspendedServers = [];
    const detectionFailedServers = [];

    for (const server of unsuspendedServers) {
      try {
        // Delay to ensure not more than one request per second
        await delay(1000);

        scanned++;
        logInfo(`Scanning server: ${server.attributes.identifier}`);

        const fileExtensions = ['.js', '.py', '.ts', '.cs', '.rs', '.lua'];
        const fileList = await traverseFiles(server.attributes.identifier, '/', fileExtensions);

        if (fileList.length === 0) {
          logInfo(`No files found for server ${server.attributes.identifier}. Skipping.`);
          continue;
        }

        let maxRating = -1;
        let allFilesFailed = true;

        for (const file of fileList) {
          try {
            // Delay for each file content fetch
            await delay(1000);

            const fileContent = await fetchFileContent(server.attributes.identifier, file);

            if (fileContent.length < 300) {
              logInfo(`File ${file} is either empty or less than 300 characters long. Skipping.`);
              continue;
            }

            // Delay before each AI detection
            await delay(1000);

            const response = await deactai(fileContent);
            const rating = response.data.rating;

            if (rating === false) {
              logInfo(`Detection failed for file ${file} on server ${server.attributes.identifier}. Logging and continuing.`);
              continue;
            }

            allFilesFailed = false;
            maxRating = Math.max(maxRating, rating);
          } catch (fileError) {
            logError(`Error processing file ${file} on server ${server.attributes.identifier}: ${fileError.message}`);
          }
        }

        if (allFilesFailed) {
          detectionFailedServers.push(server);
          logInfo(`Detection failed for all files on server ${server.attributes.identifier}. Logging and continuing.`);
          continue;
        }

        logInfo(`Max rating for server ${server.attributes.identifier}: ${maxRating}`);

        if (maxRating > 8) {
          suspicious++;
          suspiciousServers.push(server);
          logInfo(`Server ${server.attributes.identifier} marked as suspicious.`);

          if (maxRating === 10) {
            suspended++;

            // Delay before suspending the server
            await delay(1000);

            await axios.post(`${BASE_URL}/application/servers/${server.attributes.id}/suspend`, {}, { headers: HEADERS });
            suspendedServers.push(server);
            logInfo(`Server ${server.attributes.identifier} has been suspended.`);
          }
        }
      } catch (error) {
        logError(`Error processing server ${server.attributes.identifier}: ${error.message}`);
      }
    }

    const endTime = Date.now();
    const timeTaken = (endTime - startTime) / 1000;

    fs.writeFileSync('sus_servers.json', JSON.stringify(suspiciousServers, null, 2));
    fs.writeFileSync('suspended_servers.json', JSON.stringify(suspendedServers, null, 2));
    fs.writeFileSync('servers_detection_failed.json', JSON.stringify(detectionFailedServers, null, 2));
    fs.writeFileSync('status.json', JSON.stringify({
      totalServersScanned: scanned,
      totalSuspiciousServers: suspicious,
      totalSuspendedServers: suspended,
      totalDetectionFailedServers: detectionFailedServers.length,
      totalTimeTaken: timeTaken
    }, null, 2));

    logInfo('Script completed successfully.');
  } catch (error) {
    logError(`Unexpected error: ${error.message}`);
  }
}

function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

main().catch(error => logError(`Critical error occurred: ${error.message}`));
