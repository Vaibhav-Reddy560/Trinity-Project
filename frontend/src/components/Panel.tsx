import type { ReactNode } from 'react'
import { cn } from '@/lib/utils'

export function Panel({ title, aside, children, className, bodyClassName, id }: {
  title?: string
  aside?: ReactNode
  children: ReactNode
  className?: string
  bodyClassName?: string
  id?: string
}) {
  const headingId = id ? `${id}-title` : undefined
  return (
    <section className={cn('panel flex min-w-0 flex-col', className)} aria-labelledby={headingId}>
      {title && (
        <header className="flex min-h-12 items-center justify-between gap-3 border-b border-border px-5 py-2">
          <h2 id={headingId} className="text-[0.8125rem] text-bone">{title}</h2>
          {aside && <div className="flex items-center gap-2 text-xs text-ash">{aside}</div>}
        </header>
      )}
      <div className={cn('min-w-0 flex-1 p-5', bodyClassName)}>{children}</div>
    </section>
  )
}

export function PageHeader({ crumbs, title, description, actions }: {
  crumbs?: ReactNode
  title: string
  description?: ReactNode
  actions?: ReactNode
}) {
  return (
    <header className="mb-6 flex flex-wrap items-end justify-between gap-x-8 gap-y-4 border-b border-border pb-6">
      <div className="min-w-0 max-w-3xl">
        {crumbs && <nav aria-label="Breadcrumb" className="mb-3 text-sm text-ash">{crumbs}</nav>}
        <h1 className="text-[1.6rem] leading-tight text-bone md:text-[2rem]">{title}</h1>
        {description && <div className="mt-3 text-base leading-relaxed text-bone/80">{description}</div>}
      </div>
      {actions && <div className="no-print flex flex-wrap items-center gap-2">{actions}</div>}
    </header>
  )
}
