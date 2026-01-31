'use client'

import { useState } from 'react'
import { ChevronDown, ChevronUp } from 'lucide-react'

interface TopRisksTableProps {
  onShowMore?: () => void
}

export default function TopRisksTable({ onShowMore }: TopRisksTableProps) {
  const [showAll, setShowAll] = useState(false)
  
  const risks = [
    { rank: 1, name: 'Ransomware Campaign - LockBit 3.0', score: 98, severity: 'CRITICAL', affected: 47 },
    { rank: 2, name: 'VPN Zero-Day RCE (CVE-2024-1234)', score: 92, severity: 'CRITICAL', affected: 23 },
    { rank: 3, name: 'Phishing Campaign - Finance Dept', score: 85, severity: 'HIGH', affected: 156 },
    { rank: 4, name: 'Unpatched Apache Struts', score: 78, severity: 'HIGH', affected: 12 },
    { rank: 5, name: 'Insider Threat - Data Exfiltration', score: 74, severity: 'HIGH', affected: 3 },
    { rank: 6, name: 'DDoS Attack Pattern Detected', score: 68, severity: 'MEDIUM', affected: 8 },
    { rank: 7, name: 'Weak Password Policy Violations', score: 62, severity: 'MEDIUM', affected: 89 },
    { rank: 8, name: 'Outdated SSL/TLS Certificates', score: 55, severity: 'MEDIUM', affected: 34 },
    { rank: 9, name: 'Misconfigured S3 Buckets', score: 48, severity: 'LOW', affected: 6 },
    { rank: 10, name: 'Shadow IT - Unapproved SaaS', score: 42, severity: 'LOW', affected: 67 },
  ]

  const displayedRisks = showAll ? risks : risks.slice(0, 3)

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-critical text-white'
      case 'HIGH':
        return 'bg-warning text-white'
      case 'MEDIUM':
        return 'bg-blue-500 text-white'
      case 'LOW':
        return 'bg-gray-400 text-white'
      default:
        return 'bg-gray-300 text-gray-800'
    }
  }

  const handleShowMore = () => {
    if (onShowMore) {
      onShowMore()
    } else {
      setShowAll(!showAll)
    }
  }

  return (
    <div className="bg-white dark:bg-gray-800 rounded-md border border-gray-200 dark:border-gray-700 p-4 transition-colors">
      <h3 className="text-base font-semibold text-gray-900 dark:text-white mb-3">Top Risks Right Now</h3>
      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-gray-200 dark:border-gray-700">
              <th className="text-left py-1.5 px-2 font-semibold text-gray-700 dark:text-white">#</th>
              <th className="text-left py-1.5 px-2 font-semibold text-gray-700 dark:text-white">Risk Name</th>
              <th className="text-left py-1.5 px-2 font-semibold text-gray-700 dark:text-white">Score</th>
              <th className="text-left py-1.5 px-2 font-semibold text-gray-700 dark:text-white">Severity</th>
              <th className="text-left py-1.5 px-2 font-semibold text-gray-700 dark:text-white">Affected</th>
            </tr>
          </thead>
          <tbody>
            {displayedRisks.map((risk) => (
              <tr
                key={risk.rank}
                className="border-b border-gray-100 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 cursor-pointer transition-colors"
              >
                <td className="py-2 px-2 font-medium text-gray-900 dark:text-white">{risk.rank}</td>
                <td className="py-2 px-2 text-gray-800 dark:text-white">{risk.name}</td>
                <td className="py-2 px-2">
                  <span className="font-semibold text-gray-900 dark:text-white">{risk.score}</span>
                </td>
                <td className="py-2 px-2">
                  <span
                    className={`px-1.5 py-0.5 rounded text-xs font-semibold ${getSeverityColor(
                      risk.severity
                    )}`}
                  >
                    {risk.severity}
                  </span>
                </td>
                <td className="py-2 px-2 text-gray-700 dark:text-white">{risk.affected} assets</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {!showAll && (
        <button
          onClick={handleShowMore}
          className="w-full mt-3 flex items-center justify-center space-x-1 py-2 text-primary hover:bg-blue-50 dark:hover:bg-gray-700 rounded transition-colors text-sm font-medium"
        >
          <span>Show More</span>
          <ChevronDown className="w-4 h-4" />
        </button>
      )}
      {showAll && (
        <button
          onClick={() => setShowAll(false)}
          className="w-full mt-3 flex items-center justify-center space-x-1 py-2 text-primary hover:bg-blue-50 dark:hover:bg-gray-700 rounded transition-colors text-sm font-medium"
        >
          <span>Show Less</span>
          <ChevronUp className="w-4 h-4" />
        </button>
      )}
    </div>
  )
}
