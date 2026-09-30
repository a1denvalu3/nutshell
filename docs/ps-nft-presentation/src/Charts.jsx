import React, { useMemo } from 'react'
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  LabelList,
} from 'recharts'

const MUTED = '#80708f'
const BORDER = '#dbd6e1'

const CAT = [
  '#4e79a7',
  '#f28e2b',
  '#e15759',
  '#76b7b2',
  '#59a14f',
  '#edc948',
  '#b07aa1',
  '#ff9da7',
  '#9c755f',
  '#bab0ac',
]

const ax = {
  axisLine: { stroke: BORDER },
  tickLine: false,
  tick: { fill: MUTED, fontSize: 11, fontFamily: 'Rubik, system-ui' },
}

const grid = {
  strokeDasharray: '3 3',
  stroke: '#f0edf3',
  vertical: false,
}

export function WireSizeChart() {
  const data = useMemo(
    () => [
      { name: 'Credential', bytes: 193 },
      { name: 'Presentation', bytes: 321 },
      { name: 'PrivatePresentation', bytes: 385 },
    ],
    []
  )

  return (
    <ResponsiveContainer width="100%" height={300}>
      <BarChart data={data} margin={{ top: 24, right: 20, bottom: 4, left: 0 }}>
        <CartesianGrid {...grid} />
        <XAxis dataKey="name" {...ax} />
        <YAxis
          {...ax}
          label={{
            value: 'serialized bytes',
            angle: -90,
            position: 'insideLeft',
            fill: MUTED,
            fontSize: 11,
            fontFamily: 'Rubik, system-ui',
          }}
        />
        <Tooltip
          contentStyle={{
            background: '#fff',
            border: `1px solid ${BORDER}`,
            borderRadius: 6,
            fontSize: 12,
            fontFamily: 'Rubik, system-ui',
          }}
          formatter={(v) => [`${v} B`, 'size']}
        />
        <Bar dataKey="bytes" fill={CAT[0]} radius={[3, 3, 0, 0]} maxBarSize={90}>
          <LabelList
            dataKey="bytes"
            position="top"
            formatter={(v) => `${v} B`}
            style={{ fill: '#1c1028', fontSize: 12, fontFamily: 'Rubik, system-ui', fontWeight: 600 }}
          />
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}
