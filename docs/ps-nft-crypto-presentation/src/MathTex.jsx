import React from 'react'
import katex from 'katex'

export default function MathTex({ tex, display = false, className = '' }) {
  const html = katex.renderToString(tex, { displayMode: display, throwOnError: false })
  if (display) {
    return <div className={className} dangerouslySetInnerHTML={{ __html: html }} />
  }
  return <span className={className} dangerouslySetInnerHTML={{ __html: html }} />
}
