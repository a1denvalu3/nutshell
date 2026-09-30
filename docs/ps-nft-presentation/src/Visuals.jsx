import React from 'react'

// Hand-drawn line icons — stroke currentColor, 24x24 grid.
const Svg = ({ size = 24, children, stroke = 1.8, style }) => (
  <svg
    viewBox="0 0 24 24"
    width={size}
    height={size}
    fill="none"
    stroke="currentColor"
    strokeWidth={stroke}
    strokeLinecap="round"
    strokeLinejoin="round"
    style={style}
    aria-hidden="true"
  >
    {children}
  </svg>
)

export const Eye = (p) => (
  <Svg {...p}>
    <path d="M2 12c3-5.5 6.8-7 10-7s7 1.5 10 7c-3 5.5-6.8 7-10 7s-7-1.5-10-7z" />
    <circle cx="12" cy="12" r="2.5" />
  </Svg>
)

export const EyeOff = (p) => (
  <Svg {...p}>
    <path d="M4.5 6.5C3 8.2 2.2 10 2 12c3 5.5 6.8 7 10 7 1.8 0 3.4-.5 4.8-1.2M9 5.4c1-.3 2-.4 3-.4 3.2 0 7 1.5 10 7-.6 1.1-1.4 2.2-2.4 3.1" />
    <path d="M4 4l16 16" />
  </Svg>
)

export const Envelope = (p) => (
  <Svg {...p}>
    <rect x="2" y="5" width="20" height="14" rx="2" />
    <path d="M2.5 6.5L12 13l9.5-6.5" />
  </Svg>
)

export const Magnifier = (p) => (
  <Svg {...p}>
    <circle cx="10" cy="10" r="6" />
    <path d="M14.5 14.5L20 20" />
  </Svg>
)

export const Check = (p) => (
  <Svg {...p}>
    <path d="M4 12.5l5 5L20 6.5" />
  </Svg>
)

export const Stamp = (p) => (
  <Svg {...p}>
    <path d="M12 3c-2 0-3 1.4-3 2.8 0 2 1 3.1 1 5.2H8a2 2 0 0 0-2 2v1h12v-1a2 2 0 0 0-2-2h-2c0-2.1 1-3.2 1-5.2C15 4.4 14 3 12 3z" />
    <path d="M5 18h14M6 21h12" />
  </Svg>
)

export const Key = (p) => (
  <Svg {...p}>
    <circle cx="8" cy="15" r="4.5" />
    <path d="M11.2 11.8L20 3M16.5 6.5l2.5 2.5M13.5 9.5l2 2" />
  </Svg>
)

export const Vault = (p) => (
  <Svg {...p}>
    <rect x="3" y="4" width="18" height="17" rx="2" />
    <circle cx="12" cy="12.5" r="3.5" />
    <path d="M12 9v-1.2M12 16v1.2M8.5 12.5H7.3M16.7 12.5h-1.2" />
  </Svg>
)

export const Tombstone = (p) => (
  <Svg {...p}>
    <path d="M6.5 20v-8.5a5.5 5.5 0 0 1 11 0V20" />
    <path d="M3.5 20h17" />
    <path d="M9.5 11h5" />
  </Svg>
)

export const Wallet = (p) => (
  <Svg {...p}>
    <rect x="2" y="6" width="20" height="14" rx="2.5" />
    <path d="M2 10.5h20" />
    <circle cx="17" cy="15" r="1.1" />
  </Svg>
)

export const Plane = (p) => (
  <Svg {...p}>
    <path d="M22 2L11 13" />
    <path d="M22 2l-7 20-4-9-9-4 20-7z" />
  </Svg>
)

export const Scale = (p) => (
  <Svg {...p}>
    <path d="M12 3v18M6 21h12" />
    <path d="M12 6H5m7 0h7" />
    <path d="M5 6l-2.6 5.5a2.9 2.9 0 0 0 5.2 0L5 6zM19 6l-2.6 5.5a2.9 2.9 0 0 0 5.2 0L19 6z" />
  </Svg>
)

export const BlindMint = (p) => (
  <Svg {...p}>
    <path d="M4 20h16M6 20v-8M10 20v-8M14 20v-8M18 20v-8" />
    <path d="M12 3L3 9h18l-9-6z" />
    <rect x="4" y="10.6" width="16" height="2.6" fill="currentColor" stroke="none" rx="1" />
  </Svg>
)

export const Database = (p) => (
  <Svg {...p}>
    <ellipse cx="12" cy="5.5" rx="8" ry="3" />
    <path d="M4 5.5v13c0 1.7 3.6 3 8 3s8-1.3 8-3v-13" />
    <path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3" />
  </Svg>
)

export const FileDoc = (p) => (
  <Svg {...p}>
    <path d="M6 2.5h8l5 5v14H6v-19z" />
    <path d="M14 2.5v5h5" />
  </Svg>
)

export const Credential = (p) => (
  <Svg {...p}>
    <rect x="2" y="5" width="20" height="14" rx="2" />
    <circle cx="16.5" cy="10.5" r="2.3" />
    <path d="M5.5 10.5h6M5.5 14.5h8" />
  </Svg>
)

export const Question = (p) => (
  <Svg {...p}>
    <path d="M9 9a3 3 0 1 1 4.2 2.7c-.9.4-1.2 1-1.2 2" />
    <circle cx="12" cy="17.2" r="0.6" fill="currentColor" />
  </Svg>
)

export const XMark = (p) => (
  <Svg {...p}>
    <path d="M5 5l14 14M19 5L5 19" />
  </Svg>
)

export const Dash = (p) => (
  <Svg {...p}>
    <path d="M5 12h14" />
  </Svg>
)
