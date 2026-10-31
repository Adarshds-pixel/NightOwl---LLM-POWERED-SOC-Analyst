import clsx from 'clsx'
import type { ReactNode } from 'react'

/**
 * Minimal markdown renderer for model output.
 *
 * The explain/chat prompts ask for markdown (## headings, numbered response
 * steps, **emphasis**), and printing that raw made the AI surfaces look
 * broken next to the rest of the console. This handles exactly the subset
 * the prompts produce -- headings, ordered and unordered lists, tables, bold,
 * italics and inline code -- and treats everything else as plain text.
 *
 * Deliberately not a markdown library: this is a few dozen lines against a
 * known, machine-generated input, and it builds React nodes rather than
 * setting innerHTML, so model output can never inject markup.
 */
export function Markdown({ content, className }: { content: string; className?: string }) {
  const blocks = parseBlocks(content)

  return (
    <div className={clsx('flex flex-col gap-2 text-body text-text-dim', className)}>
      {blocks.map((block, index) => {
        if (block.kind === 'heading') {
          return (
            <h4
              key={index}
              className="mt-1 text-meta font-semibold tracking-[0.1em] text-text uppercase first:mt-0"
            >
              {inline(block.lines[0])}
            </h4>
          )
        }

        if (block.kind === 'ordered') {
          return (
            <ol key={index} className="flex flex-col gap-1.5">
              {block.lines.map((line, i) => {
                const number = block.numbers?.[i] ?? String(i + 1)
                return (
                  <li key={i} className="flex gap-2.5">
                    <span className="mt-0.5 flex h-4 min-w-4 shrink-0 items-center justify-center rounded bg-accent-violet/15 px-0.5 font-mono text-[10px] text-accent-violet">
                      {number}
                    </span>
                    <span className="min-w-0">{inline(line)}</span>
                  </li>
                )
              })}
            </ol>
          )
        }

        if (block.kind === 'table') {
          const [header, ...rows] = block.lines.map(tableCells)
          return (
            <div key={index} className="overflow-x-auto rounded-control border border-line-soft">
              <table className="w-full border-collapse text-left text-meta">
                <thead>
                  <tr className="bg-surface-2/50">
                    {header.map((cell, i) => (
                      <th key={i} className="border-b border-line-soft px-2.5 py-1.5 align-top font-semibold text-text">
                        {cellContent(cell)}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {rows.map((row, r) => (
                    <tr key={r} className="border-b border-line-soft last:border-b-0">
                      {row.map((cell, i) => (
                        <td key={i} className="px-2.5 py-1.5 align-top">
                          {cellContent(cell)}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )
        }

        if (block.kind === 'bullet') {
          return (
            <ul key={index} className="flex flex-col gap-1.5">
              {block.lines.map((line, i) => (
                <li key={i} className="flex gap-2.5">
                  <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-accent-magenta" />
                  <span className="min-w-0">{inline(line)}</span>
                </li>
              ))}
            </ul>
          )
        }

        return (
          <p key={index} className="whitespace-pre-wrap">
            {inline(block.lines.join(' '))}
          </p>
        )
      })}
    </div>
  )
}

type Block = { kind: 'heading' | 'ordered' | 'bullet' | 'table' | 'paragraph'; lines: string[]; numbers?: string[] }

function parseBlocks(content: string): Block[] {
  const blocks: Block[] = []
  let current: Block | null = null

  const push = () => {
    if (current) blocks.push(current)
    current = null
  }

  for (const raw of content.split('\n')) {
    const line = raw.trimEnd()

    if (line.trim() === '') {
      push()
      continue
    }

    const heading = /^#{1,4}\s+(.*)$/.exec(line)
    if (heading) {
      push()
      blocks.push({ kind: 'heading', lines: [heading[1]] })
      continue
    }

    if (/^\s*\|.*\|\s*$/.test(line)) {
      // A |---|:---:| separator row only marks the header; it holds no data.
      if (/^\s*\|[\s:|-]+\|\s*$/.test(line)) continue
      if (current?.kind !== 'table') {
        push()
        current = { kind: 'table', lines: [] }
      }
      current.lines.push(line)
      continue
    }

    const ordered = /^\s*(\d+)[.)]\s+(.*)$/.exec(line)
    if (ordered) {
      if (current?.kind !== 'ordered') {
        push()
        current = { kind: 'ordered', lines: [] }
      }
      // Keep the model's own number: a list interrupted by bullets would
      // otherwise restart at 1 in every block.
      current.lines.push(ordered[2])
      current.numbers = [...(current.numbers ?? []), ordered[1]]
      continue
    }

    const bullet = /^\s*[-*]\s+(.*)$/.exec(line)
    if (bullet) {
      if (current?.kind !== 'bullet') {
        push()
        current = { kind: 'bullet', lines: [] }
      }
      current.lines.push(bullet[1])
      continue
    }

    if (current?.kind !== 'paragraph') {
      push()
      current = { kind: 'paragraph', lines: [] }
    }
    current.lines.push(line.trim())
  }

  push()
  return blocks
}

function tableCells(row: string): string[] {
  return row.trim().replace(/^\|/, '').replace(/\|$/, '').split('|').map((cell) => cell.trim())
}

/** Models put <br> inside cells for line breaks; keep them as breaks
 *  without ever interpreting markup. */
function cellContent(cell: string): ReactNode[] {
  return cell.split(/<br\s*\/?>/i).flatMap((part, i) => (i === 0 ? inline(part) : [<br key={`br${i}`} />, ...inline(part)]))
}

/** Bold, italics and inline code within a line. Split on the markers, then style the
 *  captured groups -- no HTML is ever produced. */
function inline(text: string): ReactNode[] {
  return text
    .split(/(\*\*[^*]+\*\*|`[^`]+`|\*[^*\s][^*]*\*)/g)
    .filter((part) => part !== '')
    .map((part, index) => {
      if (part.startsWith('**') && part.endsWith('**')) {
        return (
          <strong key={index} className="font-semibold text-text">
            {part.slice(2, -2)}
          </strong>
        )
      }
      if (part.length > 2 && part.startsWith('*') && part.endsWith('*')) {
        return (
          <em key={index} className="italic">
            {part.slice(1, -1)}
          </em>
        )
      }
      if (part.startsWith('`') && part.endsWith('`')) {
        return (
          <code key={index} className="rounded border border-line-soft bg-surface-2 px-1 py-0.5 font-mono text-micro text-accent-magenta">
            {part.slice(1, -1)}
          </code>
        )
      }
      return <span key={index}>{part}</span>
    })
}
