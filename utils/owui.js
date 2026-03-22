import axios from "axios";
import FormData from "form-data";
import { fetchWithAuth } from "./fetch.js";

const OWUI_ENDPOINT = process.env.OWUI_ENDPOINT || "http://localhost:3000";
const OWUI_API_KEY = process.env.OWUI_API_KEY;

async function owuiRequest(endpoint, options = {}) {
  const headers = {
    "Content-Type": "application/json",
    ...options.headers,
  };

  if (OWUI_API_KEY) {
    headers["Authorization"] = `Bearer ${OWUI_API_KEY}`;
  }

  const url = `${OWUI_ENDPOINT}${endpoint.startsWith("/") ? endpoint : `/${endpoint}`}`;

  return axios({
    ...options,
    url,
    headers,
  });
}

export async function uploadFile(fileContent, filename) {
  try {
    const formData = new FormData();
    formData.append("file", Buffer.from(fileContent), {
      filename: filename,
      contentType: "text/markdown",
    });

    const response = await axios.post(
      `${OWUI_ENDPOINT}/files/?process_in_background=false`,
      formData.getBuffer(),
      {
        headers: {
          ...formData.getHeaders(),
          Authorization: OWUI_API_KEY ? `Bearer ${OWUI_API_KEY}` : "",
        },
        maxBodyLength: Infinity,
        maxContentLength: Infinity,
      }
    );

    return response.data;
  } catch (error) {
    console.error("OWUI uploadFile error:", error.response?.data || error.message);
    throw error;
  }
}

export async function addFileToKnowledge(knowledgeId, fileId) {
  try {
    const response = await axios.post(
      `${OWUI_ENDPOINT}/knowledge/${knowledgeId}/file/add`,
      { file_id: fileId },
      {
        headers: {
          "Content-Type": "application/json",
          Authorization: OWUI_API_KEY ? `Bearer ${OWUI_API_KEY}` : "",
        },
      }
    );

    return response.data;
  } catch (error) {
    console.error("OWUI addFileToKnowledge error:", error.response?.data || error.message);
    throw error;
  }
}

export async function getFileIdInKnowledge(knowledgeId, filename) {
  try {
    const response = await axios.get(
      `${OWUI_ENDPOINT}/knowledge/${knowledgeId}/files`,
      {
        headers: {
          Authorization: OWUI_API_KEY ? `Bearer ${OWUI_API_KEY}` : "",
        },
      }
    );

    const data = response.data;
    const files = data.items || [];

    const matchingFile = files.find(
      (file) => file.filename === filename || file.name === filename
    );

    return matchingFile ? matchingFile.id || matchingFile._id : null;
  } catch (error) {
    console.error("OWUI getFileIdInKnowledge error:", error.response?.data || error.message);
    throw error;
  }
}

export async function updateFileInKnowledge(knowledgeId, fileId, content, filename) {
  try {
    await axios.delete(
      `${OWUI_ENDPOINT}/files/${fileId}`,
      {
        headers: {
          Authorization: OWUI_API_KEY ? `Bearer ${OWUI_API_KEY}` : "",
        },
      }
    );

    const uploadResult = await uploadFile(content, filename);
    const newFileId = uploadResult.id || uploadResult._id;

    await addFileToKnowledge(knowledgeId, newFileId);

    return {
      success: true,
      fileId: newFileId,
      filename,
    };
  } catch (error) {
    console.error("OWUI updateFileInKnowledge error:", error.response?.data || error.message);
    throw error;
  }
}

export async function deleteFile(fileId) {
  try {
    await axios.delete(
      `${OWUI_ENDPOINT}/files/${fileId}`,
      {
        headers: {
          Authorization: OWUI_API_KEY ? `Bearer ${OWUI_API_KEY}` : "",
        },
      }
    );

    return { success: true };
  } catch (error) {
    console.error("OWUI deleteFile error:", error.response?.data || error.message);
    throw error;
  }
}

export async function deleteAllFilesFromKnowledge(knowledgeId) {
  try {
    const filesResponse = await axios.get(
      `${OWUI_ENDPOINT}/knowledge/${knowledgeId}/files`,
      {
        headers: {
          Authorization: OWUI_API_KEY ? `Bearer ${OWUI_API_KEY}` : "",
        },
      }
    );

    const data = filesResponse.data;
    const files = data.files || data || [];

    const deletePromises = files.map((file) =>
      deleteFile(file.id || file._id).catch((err) => {
        console.error(`Failed to delete file ${file.id || file._id}:`, err);
        return { success: false, error: err.message };
      })
    );

    await Promise.all(deletePromises);

    return { success: true, deletedCount: files.length };
  } catch (error) {
    console.error("OWUI deleteAllFilesFromKnowledge error:", error.response?.data || error.message);
    throw error;
  }
}

export async function checkKnowledgeExists(knowledgeId) {
  try {
    await axios.get(
      `${OWUI_ENDPOINT}/knowledge/${knowledgeId}`,
      {
        headers: {
          Authorization: OWUI_API_KEY ? `Bearer ${OWUI_API_KEY}` : "",
        },
      }
    );

    return true;
  } catch (error) {
    console.error("OWUI checkKnowledgeExists error:", error.response?.data || error.message);
    return false;
  }
}
