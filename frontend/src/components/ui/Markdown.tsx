import clsx from 'clsx'
import type { ReactNode } from 'react'

/**
 * Minimal markdown renderer for model output.
 *
 * The explain/chat prompts ask for markdown (## headings, numbered response
 * steps, **emphasis**), and printing that raw made the AI surfaces look
 * broken next to the rest of the console. This handles exactly the subset
 * the prompts produce -- headings, ordered and unordered lists, bold, and
 * inline code -- and treats everything else as plain text.
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
              {block.lines.map((line, i) => (
                <li key={i} className="flex gap-2.5">
                  <span className="mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded bg-accent-violet/15 font-mono text-[10px] text-accent-violet">
                    {i + 1}
                  </span>
                  <span className="min-w-0">{inline(line)}</span>
                </li>
              ))}
            </ol>
          )
        }

        if (block.kind === 'bullet') {
          return (
            <ul key={index} className="flex flex-col gap-1.5">
              {block.lines.map((line, i) => (
                <li key={i} className="flex gap-2.5">
                  <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-accent-cyan" />
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

type Block = { kind: 'heading' | 'ordered' | 'bullet' | 'paragraph'; lines: string[] }

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

    const ordered = /^\s*\d+[.)]\s+(.*)$/.exec(line)
    if (ordered) {
      if (current?.kind !== 'ordered') {
        push()
        current = { kind: 'ordered', lines: [] }
      }
      current.lines.push(ordered[1])
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

/** Bold and inline code within a line. Split on the markers, then style the
 *  captured groups -- no HTML is ever produced. */
function inline(text: string): ReactNode[] {
  return text
    .split(/(\*\*[^*]+\*\*|`[^`]+`)/g)
    .filter((part) => part !== '')
    .map((part, index) => {
      if (part.startsWith('**') && part.endsWith('**')) {
        return (
          <strong key={index} className="font-semibold text-text">
            {part.slice(2, -2)}
          </strong>
        )
      }
      if (part.startsWith('`') && part.endsWith('`')) {
        return (
          <code key={index} className="rounded bg-white/6 px-1 py-0.5 font-mono text-micro text-accent-cyan">
            {part.slice(1, -1)}
          </code>
        )
      }
      return <span key={index}>{part}</span>
    })
}
