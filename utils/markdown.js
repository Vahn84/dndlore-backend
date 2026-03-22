import { formatWorldDate } from "./time.js";

export function tipTapToMarkdown(tipTapObj) {
  if (!tipTapObj || tipTapObj.type !== "doc") {
    return "";
  }

  return (tipTapObj.content || []).map(blockToMarkdown).join("\n\n");
}

function blockToMarkdown(block) {
  if (!block) return "";

  switch (block.type) {
    case "paragraph":
      return paragraphToMarkdown(block);
    case "heading":
      return headingToMarkdown(block);
    case "bulletList":
      return bulletListToMarkdown(block);
    case "orderedList":
      return orderedListToMarkdown(block);
    case "codeBlock":
      return codeBlockToMarkdown(block);
    case "hr":
      return "---";
    default:
      return block.text || "";
  }
}

function paragraphToMarkdown(block) {
  const text = marksToMarkdown(block.content || []);
  return text;
}

function headingToMarkdown(block) {
  const level = block.attrs?.level || 1;
  const text = marksToMarkdown(block.content || []);
  const prefix = "#".repeat(level);
  return `${prefix} ${text}`;
}

function bulletListToMarkdown(block) {
  const items = (block.content || []).map((item) => {
    if (item.type === "listItem") {
      const text = marksToMarkdown(item.content || []);
      return `- ${text}`;
    }
    return "";
  }).filter(Boolean);

  return items.join("\n");
}

function orderedListToMarkdown(block) {
  const items = (block.content || []).map((item, index) => {
    if (item.type === "listItem") {
      const text = marksToMarkdown(item.content || []);
      return `${index + 1}. ${text}`;
    }
    return "";
  }).filter(Boolean);

  return items.join("\n");
}

function codeBlockToMarkdown(block) {
  const code = block.attrs?.language || "";
  const text = block.text || "";
  const backtick = String.fromCharCode(96);
  return `${backtick}${backtick}${backtick}${code}\n${text}${backtick}${backtick}${backtick}`;
}

function marksToMarkdown(nodes) {
  if (!nodes || !Array.isArray(nodes)) return "";

  return nodes.map((node) => {
    if (node.type === "text") {
      let text = node.text || "";
      
      if (node.marks && Array.isArray(node.marks)) {
        const sortedMarks = sortMarksByDepth(node.marks);
        const openMarks = sortedMarks.map(mark => getMarkTag(mark, true));
        const closeMarks = sortedMarks.reverse().map(mark => getMarkTag(mark, false));
        
        text = openMarks.join("") + text + closeMarks.join("");
      }
      
      return text;
    }
    
    if (node.content && Array.isArray(node.content)) {
      return marksToMarkdown(node.content);
    }
    
    return "";
  }).join("");
}

function sortMarksByDepth(marks) {
  return marks.sort((a, b) => {
    const depthA = getMarkDepth(a);
    const depthB = getMarkDepth(b);
    return depthB - depthA;
  });
}

function getMarkDepth(mark) {
  if (!mark) return 0;
  let depth = 0;
  if (mark.type === "link") depth++;
  if (mark.type === "bold") depth++;
  if (mark.type === "italic") depth++;
  return depth;
}

function getMarkTag(mark, isOpen) {
  if (!mark) return "";
  
  switch (mark.type) {
    case "bold":
      return isOpen ? "**" : "**";
    case "italic":
      return isOpen ? "_" : "_";
    case "strike":
      return isOpen ? "~~" : "~~";
    case "code":
      return String.fromCharCode(96);
    case "link":
      const href = mark.attrs?.href || "";
      const title = mark.attrs?.title || "";
      if (isOpen) {
        return "[";
      } else {
        return `](${href}${title ? ` "${title}"` : ""})`;
      }
    default:
      return "";
  }
}

export function generateFilename(page, tsConfig) {
  if (!page || !page.type) {
    return "untitled.md";
  }

  const { type, title, subtitle, worldDate, sessionDate } = page;

  switch (type) {
    case "campaign":
      if (subtitle && sessionDate) {
        return `campaign - ${subtitle}: ${title}.md`;
      } else if (subtitle) {
        return `campaign - ${subtitle}: ${title}.md`;
      } else if (sessionDate) {
        return `campaign - ${sessionDate}: ${title}.md`;
      }
      return `campaign: ${title}.md`;
    
    case "history":
      if (worldDate && worldDate.eraId) {
        const datePart = formatWorldDate(worldDate, tsConfig);
        return `history - ${datePart}: ${title}.md`;
      }
      return `history: ${title}.md`;
    
    case "place":
    case "myth":
    case "people":
      return `${type}: ${title}.md`;
    
    default:
      return `${type}: ${title}.md`;
  }
}

export function generatePageMetadata(page, tsConfig) {
  if (!page) return "";

  const { type, title, worldDate } = page;
  const metadataLines = [`# ${title}`];

  if ((type === "campaign" || type === "history") && worldDate && worldDate.eraId) {
    metadataLines.push("");
    metadataLines.push(`**World Date:** ${formatWorldDate(worldDate, tsConfig)}`);
  }

  metadataLines.push("");
  metadataLines.push("---");

  return metadataLines.join("\n");
}

export function generateMarkdownContent(page, tsConfig) {
  if (!page) return "";

  const metadata = generatePageMetadata(page, tsConfig);
  const contentBlocks = (page.blocks || []).map(block => {
    if (block.type === "rich" && block.rich) {
      return tipTapToMarkdown(block.rich);
    }
    if (block.type === "image" && block.url) {
      return `![${block.alt || ""}](${block.url})`;
    }
    return "";
  }).filter(Boolean);

  const content = contentBlocks.join("\n\n");

  return `${metadata}\n\n${content}`;
}
