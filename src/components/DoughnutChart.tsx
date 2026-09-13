import React, { useState } from 'react';

export interface DoughnutSegment {
  label: string;
  count: number;
  color: string;
}

interface DoughnutChartProps {
  data: DoughnutSegment[];
  totalLabel: string;
  title: string;
}

export const DoughnutChart: React.FC<DoughnutChartProps> = ({ data, totalLabel, title }) => {
  const [hoveredIdx, setHoveredIdx] = useState<number | null>(null);

  const total = data.reduce((sum, item) => sum + item.count, 0);

  if (total === 0) {
    return (
      <div className="flex flex-col items-center justify-center p-6 text-center border border-dashed border-slate-200 rounded-lg">
        <div className="w-32 h-32 rounded-full border-4 border-slate-100 flex items-center justify-center">
          <span className="text-xs text-slate-400 font-mono">0 записей</span>
        </div>
        <p className="text-xs text-slate-500 mt-3">{title} — пока нет данных</p>
      </div>
    );
  }

  // Calculate SVG arc paths
  const radius = 70;
  const strokeWidth = 24;
  const center = 100;
  let cumulativeAngle = 0;

  const segments = data
    .filter((d) => d.count > 0)
    .map((d, index) => {
      const percentage = (d.count / total) * 100;
      const angle = (d.count / total) * 360;
      const startAngle = cumulativeAngle;
      const endAngle = cumulativeAngle + angle;
      cumulativeAngle += angle;

      // Coordinate math
      const startRad = ((startAngle - 90) * Math.PI) / 180;
      const endRad = ((endAngle - 90) * Math.PI) / 180;

      const x1 = center + radius * Math.cos(startRad);
      const y1 = center + radius * Math.sin(startRad);
      const x2 = center + radius * Math.cos(endRad);
      const y2 = center + radius * Math.sin(endRad);

      const largeArcFlag = angle > 180 ? 1 : 0;
      const isSingleSegment = angle >= 359.99;

      let pathData = '';
      if (isSingleSegment) {
        // Full circle
        pathData = `M ${center} ${center - radius} A ${radius} ${radius} 0 1 1 ${center - 0.001} ${center - radius} Z`;
      } else {
        pathData = `M ${x1} ${y1} A ${radius} ${radius} 0 ${largeArcFlag} 1 ${x2} ${y2}`;
      }

      return {
        ...d,
        index,
        percentage,
        pathData,
        isSingleSegment,
      };
    });

  const activeSegment = hoveredIdx !== null ? segments.find((s) => s.index === hoveredIdx) : null;

  return (
    <div className="flex flex-col sm:flex-row items-center gap-6">
      {/* SVG Doughnut */}
      <div className="relative w-48 h-48 shrink-0 flex items-center justify-center">
        <svg viewBox="0 0 200 200" className="w-full h-full transform -rotate-90">
          {segments.map((seg) => {
            const isHovered = hoveredIdx === seg.index;
            if (seg.isSingleSegment) {
              return (
                <circle
                  key={seg.index}
                  cx={center}
                  cy={center}
                  r={radius}
                  fill="none"
                  stroke={seg.color}
                  strokeWidth={isHovered ? strokeWidth + 4 : strokeWidth}
                  className="transition-all duration-200 cursor-pointer"
                  onMouseEnter={() => setHoveredIdx(seg.index)}
                  onMouseLeave={() => setHoveredIdx(null)}
                />
              );
            }

            return (
              <path
                key={seg.index}
                d={seg.pathData}
                fill="none"
                stroke={seg.color}
                strokeWidth={isHovered ? strokeWidth + 4 : strokeWidth}
                strokeLinecap="butt"
                className="transition-all duration-200 cursor-pointer hover:opacity-90"
                onMouseEnter={() => setHoveredIdx(seg.index)}
                onMouseLeave={() => setHoveredIdx(null)}
              />
            );
          })}
        </svg>

        {/* Center label */}
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none text-center">
          <span className="text-2xl font-bold text-slate-800 font-mono leading-tight">
            {activeSegment ? activeSegment.count : total}
          </span>
          <span className="text-[11px] text-slate-500 font-medium px-2 truncate max-w-[120px]">
            {activeSegment ? activeSegment.label : totalLabel}
          </span>
          {activeSegment && (
            <span className="text-[10px] text-slate-400 font-mono mt-0.5">
              {activeSegment.percentage.toFixed(1)}%
            </span>
          )}
        </div>
      </div>

      {/* Legend list */}
      <div className="flex-1 w-full space-y-1.5 text-xs">
        {data.map((item, idx) => {
          const isHovered = hoveredIdx === idx;
          const percentage = total > 0 ? ((item.count / total) * 100).toFixed(0) : '0';
          return (
            <div
              key={idx}
              onMouseEnter={() => setHoveredIdx(idx)}
              onMouseLeave={() => setHoveredIdx(null)}
              className={`flex items-center justify-between p-1.5 rounded transition cursor-pointer ${
                isHovered ? 'bg-slate-100 font-semibold' : 'hover:bg-slate-50 text-slate-700'
              }`}
            >
              <div className="flex items-center gap-2 min-w-0">
                <span
                  className="w-2.5 h-2.5 rounded-full shrink-0"
                  style={{ backgroundColor: item.color }}
                />
                <span className="truncate">{item.label}</span>
              </div>
              <div className="flex items-center gap-2 font-mono shrink-0 pl-2">
                <span>{item.count}</span>
                <span className="text-slate-400 text-[10px] w-8 text-right">({percentage}%)</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
