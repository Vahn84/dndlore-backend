import { formatWorldDate } from "./time.js";

export function markdownToTipTap(markdownText) {
  if (!markdownText || typeof markdownText !== 'string') {
    return null;
  }

  const lines = markdownText.split('\n');
  const content = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    // Code blocks
    if (line.startsWith('```')) {
      const codeLang = line.slice(3).trim();
      const codeLines = [];
      i++;
      while (i < lines.length && !lines[i].startsWith('```')) {
        codeLines.push(lines[i]);
        i++;
      }
      content.push({
        type: 'codeBlock',
        attrs: { language: codeLang || null },
        text: codeLines.join('\n')
      });
      i++;
      continue;
    }

    // Headings
    const headingMatch = line.match(/^(#{1,6})\s+(.*)$/);
    if (headingMatch) {
      content.push({
        type: 'heading',
        attrs: { level: headingMatch[1].length },
        content: parseInlineContent(headingMatch[2]),
      });
      i++;
      continue;
    }

    // Blockquotes
    if (line.startsWith('>')) {
      const quoteLines = [];
      while (i < lines.length && lines[i].startsWith('>')) {
        quoteLines.push(lines[i].replace(/^>\s?/, ''));
        i++;
      }
      content.push({
        type: 'blockquote',
        content: [{
          type: 'paragraph',
          content: parseInlineContent(quoteLines.join('\n')),
        }]
      });
      continue;
    }

    // Horizontal rule
    if (line.match(/^[-*_]{3,}$/)) {
      content.push({ type: 'hr' });
      i++;
      continue;
    }

    // Bullet lists
    if (line.match(/^[\-\*]\s+/)) {
      const listItems = [];
      while (i < lines.length && lines[i].match(/^[\-\*]\s+/)) {
        const itemText = lines[i].replace(/^[\-\*]\s+/, '');
        listItems.push({
          type: 'listItem',
          content: [{
            type: 'paragraph',
            content: parseInlineContent(itemText),
          }]
        });
        i++;
      }
      content.push({
        type: 'bulletList',
        content: listItems
      });
      continue;
    }

    // Ordered lists
    if (line.match(/^\d+\.\s+/)) {
      const listItems = [];
      while (i < lines.length && lines[i].match(/^\d+\.\s+/)) {
        const itemText = lines[i].replace(/^\d+\.\s+/, '');
        listItems.push({
          type: 'listItem',
          content: [{
            type: 'paragraph',
            content: parseInlineContent(itemText),
          }]
        });
        i++;
      }
      content.push({
        type: 'orderedList',
        content: listItems
      });
      continue;
    }

    // Regular paragraphs
    if (line.trim()) {
      content.push({
        type: 'paragraph',
        content: parseInlineContent(line),
      });
    }
    i++;
  }

  return content.length > 0 ? { type: 'doc', content } : null;
}

/**
 * Parse inline markdown into an array of TipTap content nodes.
 * Each bold/italic span becomes its own text node with the appropriate mark.
 */
function parseInlineContent(text) {
  if (!text) return [{ type: 'text', text: '' }];

  const nodes = [];
  let remaining = text;

  while (remaining.length > 0) {
    // Bold: **text**
    const boldMatch = remaining.match(/^\*\*(.+?)\*\*/s);
    if (boldMatch) {
      nodes.push({ type: 'text', text: boldMatch[1], marks: [{ type: 'bold' }] });
      remaining = remaining.slice(boldMatch[0].length);
      continue;
    }

    // Italic: *text*
    const italicStarMatch = remaining.match(/^\*([^*\n]+?)\*/);
    if (italicStarMatch) {
      nodes.push({ type: 'text', text: italicStarMatch[1], marks: [{ type: 'italic' }] });
      remaining = remaining.slice(italicStarMatch[0].length);
      continue;
    }

    // Italic: _text_
    const italicUnderMatch = remaining.match(/^_([^_\n]+?)_/);
    if (italicUnderMatch) {
      nodes.push({ type: 'text', text: italicUnderMatch[1], marks: [{ type: 'italic' }] });
      remaining = remaining.slice(italicUnderMatch[0].length);
      continue;
    }

    // Strike: ~~text~~
    const strikeMatch = remaining.match(/^~~(.+?)~~/s);
    if (strikeMatch) {
      nodes.push({ type: 'text', text: strikeMatch[1], marks: [{ type: 'strike' }] });
      remaining = remaining.slice(strikeMatch[0].length);
      continue;
    }

    // Link: [text](url)
    const linkMatch = remaining.match(/^\[([^\]]+)\]\(([^)]+)\)/);
    if (linkMatch) {
      nodes.push({ type: 'text', text: linkMatch[1], marks: [{ type: 'link', attrs: { href: linkMatch[2] } }] });
      remaining = remaining.slice(linkMatch[0].length);
      continue;
    }

    // Plain text: consume until the next marker
    const plainMatch = remaining.match(/^([\s\S]+?)(?=\*\*|\*|_(?=[^_])|~~|\[)|^([\s\S]+)$/);
    if (plainMatch) {
      const plain = plainMatch[1] ?? plainMatch[2];
      nodes.push({ type: 'text', text: plain });
      remaining = remaining.slice(plain.length);
    } else {
      nodes.push({ type: 'text', text: remaining[0] });
      remaining = remaining.slice(1);
    }
  }

  return nodes.length > 0 ? nodes : [{ type: 'text', text: text }];
}

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
      return `${type} - ${title}.md`;

    default:
      return `${type} - ${title}.md`;
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
