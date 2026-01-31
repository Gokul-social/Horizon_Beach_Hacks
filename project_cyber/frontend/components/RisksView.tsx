import { useState } from 'react'
import AgentDiscussionModal from './AgentDiscussionModal'
import PlaybookModal from './PlaybookModal'
import { PLAYBOOKS, Playbook } from '../utils/playbooks'

export default function RisksView() {
  const [isModalOpen, setIsModalOpen] = useState(false)
  const [currentRiskName, setCurrentRiskName] = useState('')
  const [messages, setMessages] = useState<any[]>([])
  const [isLoading, setIsLoading] = useState(false)

  // Playbook Modal State
  const [isPlaybookModalOpen, setIsPlaybookModalOpen] = useState(false)
  const [currentPlaybook, setCurrentPlaybook] = useState<Playbook | null>(null)
  const [currentRiskIdForPlaybook, setCurrentRiskIdForPlaybook] = useState<number | null>(null)

  const [risks, setRisks] = useState([
    { rank: 1, name: 'Ransomware Campaign - LockBit 3.0', score: 98, severity: 'CRITICAL', affected: 47, category: 'Malware', lastDetected: '2m ago' },
    { rank: 2, name: 'VPN Zero-Day RCE (CVE-2024-1234)', score: 92, severity: 'CRITICAL', affected: 23, category: 'Vulnerability', lastDetected: '15m ago' },
    { rank: 3, name: 'Phishing Campaign - Finance Dept', score: 85, severity: 'HIGH', affected: 156, category: 'Social Engineering', lastDetected: '1h ago' },
    { rank: 4, name: 'Unpatched Apache Struts', score: 78, severity: 'HIGH', affected: 12, category: 'Vulnerability', lastDetected: '3h ago' },
    { rank: 5, name: 'Insider Threat - Data Exfiltration', score: 74, severity: 'HIGH', affected: 3, category: 'Insider Threat', lastDetected: '5h ago' },
    { rank: 6, name: 'DDoS Attack Pattern Detected', score: 68, severity: 'MEDIUM', affected: 8, category: 'Network Attack', lastDetected: '8h ago' },
    { rank: 7, name: 'Weak Password Policy Violations', score: 62, severity: 'MEDIUM', affected: 89, category: 'Policy Violation', lastDetected: '12h ago' },
    { rank: 8, name: 'Outdated SSL/TLS Certificates', score: 55, severity: 'MEDIUM', affected: 34, category: 'Configuration', lastDetected: '1d ago' },
    { rank: 9, name: 'Misconfigured S3 Buckets', score: 48, severity: 'LOW', affected: 6, category: 'Cloud Security', lastDetected: '2d ago' },
    { rank: 10, name: 'Shadow IT - Unapproved SaaS', score: 42, severity: 'LOW', affected: 67, category: 'Policy Violation', lastDetected: '3d ago' },
  ])

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

  const handlePlaybookClick = (risk: any) => {
    const name = risk.name.toLowerCase();
    const category = risk.category.toLowerCase();

    // Logic to select the correct playbook based on risk
    let playbookKey = '';

    if (name.includes('ransomware') || name.includes('malware') || category.includes('malware')) {
      playbookKey = 'malware-containment';
    } else if (name.includes('disconnect') || name.includes('ddos') || category.includes('network')) {
      playbookKey = 'malware-containment'; // Use containment for network attacks too as a fallback
    } else {
      // Default to data breach for phishing, insider threat, policy violations etc that might lead to data leaks
      playbookKey = 'data-breach-response';
    }

    // Specific overrides
    if (name.includes('unpatched') || name.includes('vulnerability')) {
      playbookKey = 'malware-containment'; // Patching often involves containment first
    }

    const playbook = PLAYBOOKS[playbookKey];
    if (playbook) {
      setCurrentPlaybook(playbook);
      setCurrentRiskIdForPlaybook(risk.rank);
      setIsPlaybookModalOpen(true);
    }
  }

  // Backup risks to replenish the list
  const BACKUP_RISKS = [
    { name: 'API Key Leak - GitHub', score: 95, severity: 'CRITICAL', affected: 1, category: 'Data Leak', lastDetected: '10m ago' },
    { name: 'Suspicious PowerShell Execution', score: 88, severity: 'HIGH', affected: 5, category: 'Malware', lastDetected: '20m ago' },
    { name: 'RDP Brute Force Attack', score: 82, severity: 'HIGH', affected: 2, category: 'Network Attack', lastDetected: '45m ago' },
    { name: 'Unusual Data Transfer - Marketing', score: 70, severity: 'MEDIUM', affected: 1, category: 'Insider Threat', lastDetected: '1h ago' },
    { name: 'New Admin Account Created', score: 65, severity: 'MEDIUM', affected: 1, category: 'Privilege Escalation', lastDetected: '2h ago' },
    { name: 'Port 445 Open Exposure', score: 58, severity: 'MEDIUM', affected: 3, category: 'Configuration', lastDetected: '4h ago' },
    { name: 'Failed Login Anomalies', score: 50, severity: 'LOW', affected: 15, category: 'Identity', lastDetected: '6h ago' }
  ];

  const handleMitigateRisk = () => {
    if (currentRiskIdForPlaybook !== null) {
      setRisks(prevRisks => {
        // 1. Remove the mitigated risk
        const filtered = prevRisks.filter(r => r.rank !== currentRiskIdForPlaybook);

        // 2. Find a new risk from backup that is NOT in the current filtered list
        // Simple check by name
        const currentNames = new Set(filtered.map(r => r.name));
        const availableBackup = BACKUP_RISKS.find(backup => !currentNames.has(backup.name));

        let newRisksList = [...filtered];

        if (availableBackup) {
          // Add the new risk to the end (initially)
          newRisksList.push({ ...availableBackup, rank: 0 }); // Rank will be fixed below
        }

        // 3. Sort by score (descending) and re-rank everyone 1 to N
        newRisksList.sort((a, b) => b.score - a.score);
        return newRisksList.map((risk, index) => ({ ...risk, rank: index + 1 }));
      });
      setIsPlaybookModalOpen(false);
      setCurrentRiskIdForPlaybook(null);
    }
  }

  const handleAgentDiscussion = async (riskName: string) => {
    setCurrentRiskName(riskName)
    setIsModalOpen(true)
    setIsLoading(true)
    setMessages([])

    try {
      // Simulate API call or Real API call
      // In a real scenario, we would use the incident ID. Here we use a 'demo' ID for demonstration.
      const encodedRiskName = encodeURIComponent(riskName)
      const response = await fetch(`http://localhost:8000/api/agents/analyze/demo?risk_title=${encodedRiskName}&agents=analyst&agents=intel&agents=forensics&agents=business`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        // We can pass body if needed, currently endpoint takes query params for agents
      })

      if (response.ok) {
        const data = await response.json()
        // If the backend returns structured consensus/messages, we parse it.
        // For now, if the backend is mocked to return 'messages', let's use that.
        // If backend returns standard response, we might need to map it.
        if (data.discussion) {
          setMessages(data.discussion)
        } else {
          // Fallback if backend structure isn't exactly matched yet
          setMessages(generateMockDiscussion(riskName))
        }
      } else {
        // Fallback to mock if API fails (e.g. backend not running or auth error)
        console.warn('Backend API unavailable, using simulation.')
        await new Promise(resolve => setTimeout(resolve, 2000)) // Simulate network delay
        setMessages(generateMockDiscussion(riskName))
      }
    } catch (error) {
      console.error('Failed to fetch explanation', error)
      await new Promise(resolve => setTimeout(resolve, 1500))
      setMessages(generateMockDiscussion(riskName))
    } finally {
      setIsLoading(false)
    }
  }

  const generateMockDiscussion = (riskName: string) => {
    const titleLower = riskName.toLowerCase()

    // Helper functions for dynamic data
    const getRandomIP = () => `${Math.floor(Math.random() * 182 + 10)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 254 + 1)}`
    const getRandomUser = () => {
      const users = ['j.doe', 'm.smith', 'a.jones', 'c.lee', 'finance_admin', 'sys_operator', 'k.patel']
      return users[Math.floor(Math.random() * users.length)]
    }
    const getRandomFile = () => {
      const files = ['payroll_2025.db', 'client_list.xlsx', 'passwords.txt', 'network_map.vsd', 'marketing_budget.pptx', 'secret_project.pdf']
      return files[Math.floor(Math.random() * files.length)]
    }
    const getRandomMoney = () => `$${Math.floor(Math.random() * 190 + 10)}k/hour`
    const getTime = (offset: number) => {
      const d = new Date()
      d.setSeconds(d.getSeconds() + offset)
      return d.toLocaleTimeString('en-US', { hour12: false })
    }

    // Helper to pick random message
    const pick = (options: string[]) => options[Math.floor(Math.random() * options.length)]

    if (titleLower.includes('ransomware') || titleLower.includes('lockbit')) {
      const analystMsgs = [
        `Team, urgent alert! 🚨 I'm seeing a massive spike in file writes on the Finance VLAN. ${Math.floor(Math.random() * 600 + 300)} files encrypted in the last minute. It looks like ransomware.`,
        `Critical Alert: Anomaly detection system has flagged simultaneous file encryption on ${Math.floor(Math.random() * 10 + 5)} endpoints. Signature resembles LockBit.`,
        `I'm detecting high-IOPS activity matching ransomware behavior on subnet 10.20.5.x. Multiple users reporting 'cannot open files'.`
      ]
      const intelMsgs = [
        `On it. Checking the file artifacts... Okay, the extension signature matches **LockBit 3.0**. They've been active in our sector this week.`,
        `Threat Intelligence Feed correlation confirms this is **BlackBase** or **LockBit** variant. C2 traffic is going to ${getRandomIP()}.`,
        `Confirmed. This hash was seen 4 hours ago in a bulletin for the Financial sector. It's a double-extortion campaign.`
      ]
      const forensicsMsgs = [
        `Tracing the entry point... Found it. Reviewing the logs on Server-DB-04. Someone brute-forced RDP for user '${getRandomUser()}'. I see a 'Mimikatz' dump in the temp folder.`,
        `Patient Zero identified. Workstation ${getRandomIP()} executed a malicious macro. I found a PowerShell script running in memory.`,
        `Analysis of the dropped binary shows it kills SQL services before encrypting. It entered via an unpatched Exchange vulnerability.`
      ]
      const businessMsgs = [
        `Calculated impact: That server holds the ${pick(['payroll', 'customer', 'legal'])} data. If we lose it, we face severe compliance fines. Impact: ${getRandomMoney()}.`,
        `Stop the bleeding! That segment processes $${Math.floor(Math.random() * 9 + 1)}M in daily transactions. We cannot afford downtime > 1 hour.`,
        `Legal is asking if we need to declare a breach. If data left the building, we have 72 hours to notify regulators.`
      ]

      return [
        { agent: 'analyst', message: pick(analystMsgs), timestamp: getTime(0) },
        { agent: 'intel', message: pick(intelMsgs), timestamp: getTime(3) },
        { agent: 'forensics', message: pick(forensicsMsgs), timestamp: getTime(8) },
        { agent: 'business', message: pick(businessMsgs), timestamp: getTime(15) },
        { agent: 'analyst', message: "Isolating the infected subnet now to prevent lateral movement.", timestamp: getTime(18) },
        { agent: 'forensics', message: "Capturing memory dump for decryptor extraction.", timestamp: getTime(21) }
      ]
    }
    else if (titleLower.includes('phishing')) {
      const domain = `login-${pick(['secure', 'update', 'verify', 'support'])}-microsoft.com`
      return [
        { agent: 'analyst', message: `Hey Intel, are you seeing this domain '${domain}'? ${Math.floor(Math.random() * 40 + 10)} users just clicked it from an email labeled 'Urgent Invoice'.`, timestamp: getTime(0) },
        { agent: 'intel', message: `Checking whois data... It was registered ${Math.floor(Math.random() * 10 + 2)} hours ago via NameCheap. Definitely malicious credential harvester.`, timestamp: getTime(5) },
        { agent: 'forensics', message: `I'm looking at the endpoint logs. ${Math.floor(Math.random() * 4 + 2)} users actually entered credentials. I see a POST request with their hashes.`, timestamp: getTime(12) },
        { agent: 'business', message: "Three compromised accounts? We need to force reset those passwords immediately. One of them is a VIP account.", timestamp: getTime(18) },
        { agent: 'analyst', message: "Executing 'Account_Compromise_Containment' playbook. Revoking sessions.", timestamp: getTime(21) }
      ]
    }
    else if (titleLower.includes('vpn') || titleLower.includes('cve') || titleLower.includes('unpatched') || titleLower.includes('vulnerability')) {
      const cve = `CVE-202${Math.floor(Math.random() * 2 + 4)}-${Math.floor(Math.random() * 8999 + 1000)}`
      return [
        { agent: 'analyst', message: `Critical Alert: Vulnerability Scanner is flagging our VPN gateway for ${cve}. It's a 9.8 Severity RCE.`, timestamp: getTime(0) },
        { agent: 'intel', message: `I confirm. Exploit code was just published on Twitter/X. Threat actors are actively scanning for this. We are exposed.`, timestamp: getTime(4) },
        { agent: 'forensics', message: `Checking firewall logs... I see connection attempts from ${getRandomIP()} trying to trigger the buffer overflow.`, timestamp: getTime(9) },
        { agent: 'analyst', message: "We need to patch immediately. The attack surface is too wide to block IPs.", timestamp: getTime(12) },
        { agent: 'business', message: "It's mid-day. Patching takes down the remote sales team. Can we wait 4 hours?", timestamp: getTime(20) },
        { agent: 'intel', message: "Too risky. If they get in, they deploy ransomware. Downtime cost < Breach cost.", timestamp: getTime(23) },
        { agent: 'business', message: "Authorized. Deploy the hotfix now.", timestamp: getTime(25) }
      ]
    }
    else if (titleLower.includes('insider') || titleLower.includes('exfiltration')) {
      const user = getRandomUser()
      const file = getRandomFile()
      return [
        { agent: 'analyst', message: `DLP Alert: User '${user}' is uploading huge files to personal cloud. ${Math.floor(Math.random() * 8 + 2)}GB transferred in 10 minutes.`, timestamp: getTime(0) },
        { agent: 'intel', message: `Context check: '${user}' just submitted a resignation letter 2 days ago. Flight risk confirmed.`, timestamp: getTime(3) },
        { agent: 'forensics', message: `I've identified the files. It's '${file}' and the customer database. This isn't personal data.`, timestamp: getTime(8) },
        { agent: 'analyst', message: "I'm killing the session and disabling the account. Access revoked.", timestamp: getTime(11) },
        { agent: 'business', message: "Notify Legal. We need to send a cease & desist. That intellectual property is valued at $5M+.", timestamp: getTime(14) }
      ]
    }
    else if (titleLower.includes('ddos')) {
      return [
        { agent: 'analyst', message: `Traffic spike! ${Math.floor(Math.random() * 80 + 40)} Gbps hitting the main load balancer. API latency is through the roof.`, timestamp: getTime(0) },
        { agent: 'forensics', message: "It's volumetric UDP flood. Reflection info showing DNS and NTP amplification vectors.", timestamp: getTime(4) },
        { agent: 'intel', message: "Botnet signature matches. This looks like a paid 'Stresser' attack hired by a competitor.", timestamp: getTime(9) },
        { agent: 'business', message: `Our SLAs are breaching. Costs are racking up at ${getRandomMoney()}. Fix it!`, timestamp: getTime(12) },
        { agent: 'analyst', message: "Activating CloudFlare 'Under Attack' mode. Rerouting traffic.", timestamp: getTime(15) },
        { agent: 'business', message: "Traffic normalizing. Good work.", timestamp: getTime(18) }
      ]
    }
    else if (titleLower.includes('s3') || titleLower.includes('cloud')) {
      return [
        { agent: 'analyst', message: "CSPM Alert: S3 bucket 'production-data' was just made PUBLIC. ⚠️", timestamp: getTime(0) },
        { agent: 'forensics', message: `CloudTrail says user '${getRandomUser()}' made the change via CLI. Likely an accident.`, timestamp: getTime(3) },
        { agent: 'intel', message: "Public scanners are already hitting it. I see connections from unknown IPs.", timestamp: getTime(7) },
        { agent: 'analyst', message: "Remediated. Permissions reverted to Private. Access blocked.", timestamp: getTime(11) },
        { agent: 'business', message: "We need to audit what was accessed. If PII was leaked, we have regulatory reporting duties.", timestamp: getTime(14) }
      ]
    }
    else if (titleLower.includes('policy') || titleLower.includes('password') || titleLower.includes('shadow')) {
      return [
        { agent: 'analyst', message: "Audit finding: 30% of accounts have weak passwords. Also detecting unauthorized Notion usage.", timestamp: getTime(0) },
        { agent: 'intel', message: "Those Notion pages are indexed on Google. I found our Q3 roadmap publicly visible.", timestamp: getTime(5) },
        { agent: 'business', message: "Take it down immediately! That contains unreleased product features.", timestamp: getTime(10) },
        { agent: 'analyst', message: "Blocking Notion at the CASB level. Enforcing MFA for all users tonight.", timestamp: getTime(16) }
      ]
    }
    else {
      // Fallback
      return [
        { agent: 'analyst', message: `Team, correlating multiple alerts on '${riskName}'. Traffic volume is abnormal.`, timestamp: getTime(0) },
        { agent: 'intel', message: `I'm checking threat feeds... No direct matches for this specific signature yet, but it resembles known C2 behavior.`, timestamp: getTime(3) },
        { agent: 'forensics', message: `Checking... Yes, found a suspicious process spawning from svchost. It's beaconing out to an unknown IP.`, timestamp: getTime(8) },
        { agent: 'business', message: `What system is this?`, timestamp: getTime(11) },
        { agent: 'analyst', message: `It's the backup customer support portal.`, timestamp: getTime(13) },
        { agent: 'business', message: `Okay, non-critical for revenue, but protect the data. Isolate it.`, timestamp: getTime(15) }
      ]
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Top 10 Risks Dashboard</h1>
        <div className="flex items-center space-x-2">
          <button className="px-4 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-md text-sm font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
            Filter
          </button>
          <button className="px-4 py-2 bg-primary text-white rounded-md text-sm font-medium hover:bg-primary-dark transition-colors">
            Export Report
          </button>
        </div>
      </div>

      <div className="bg-white dark:bg-gray-800 rounded-md border border-gray-200 dark:border-gray-700 p-6 transition-colors">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b-2 border-gray-200 dark:border-gray-700">
                <th className="text-left py-3 px-3 font-semibold text-gray-700 dark:text-white">Rank</th>
                <th className="text-left py-3 px-3 font-semibold text-gray-700 dark:text-white">Risk Name</th>
                <th className="text-left py-3 px-3 font-semibold text-gray-700 dark:text-white">Category</th>
                <th className="text-left py-3 px-3 font-semibold text-gray-700 dark:text-white">Score</th>
                <th className="text-left py-3 px-3 font-semibold text-gray-700 dark:text-white">Severity</th>
                <th className="text-left py-3 px-3 font-semibold text-gray-700 dark:text-white">Affected Assets</th>
                <th className="text-left py-3 px-3 font-semibold text-gray-700 dark:text-white">Last Detected</th>
                <th className="text-left py-3 px-3 font-semibold text-gray-700 dark:text-white">Actions</th>
              </tr>
            </thead>
            <tbody>
              {risks.map((risk) => (
                <tr
                  key={risk.rank}
                  className="border-b border-gray-100 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 cursor-pointer transition-colors"
                >
                  <td className="py-4 px-3 font-bold text-gray-900 dark:text-white">{risk.rank}</td>
                  <td className="py-4 px-3 text-gray-800 dark:text-white font-medium">{risk.name}</td>
                  <td className="py-4 px-3 text-gray-600 dark:text-white">{risk.category}</td>
                  <td className="py-4 px-3">
                    <span className="font-bold text-gray-900 dark:text-white text-base">{risk.score}</span>
                  </td>
                  <td className="py-4 px-3">
                    <span
                      className={`px-2 py-1 rounded text-xs font-semibold ${getSeverityColor(
                        risk.severity
                      )}`}
                    >
                      {risk.severity}
                    </span>
                  </td>
                  <td className="py-4 px-3 text-gray-700 dark:text-white">{risk.affected} assets</td>
                  <td className="py-4 px-3 text-gray-600 dark:text-white">{risk.lastDetected}</td>
                  <td className="py-4 px-3">
                    <div className="flex gap-2">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleAgentDiscussion(risk.name);
                        }}
                        className="px-3 py-1 bg-primary text-white rounded text-xs font-medium hover:bg-primary-dark transition-colors"
                      >
                        Agent Discussion
                      </button>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handlePlaybookClick(risk);
                        }}
                        className="px-3 py-1 bg-white border border-gray-300 text-gray-700 rounded text-xs font-medium hover:bg-gray-50 dark:bg-gray-800 dark:border-gray-600 dark:text-gray-300 dark:hover:bg-gray-700 transition-colors"
                      >
                        Playbook
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <AgentDiscussionModal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        riskName={currentRiskName}
        messages={messages}
        isLoading={isLoading}
      />

      <PlaybookModal
        isOpen={isPlaybookModalOpen}
        onClose={() => setIsPlaybookModalOpen(false)}
        playbook={currentPlaybook}
        onMitigate={handleMitigateRisk}
      />
    </div>
  )
}
