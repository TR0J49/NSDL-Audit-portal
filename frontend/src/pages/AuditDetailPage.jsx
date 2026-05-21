import { useState, useEffect } from 'react'
import { useParams } from 'react-router-dom'
import { motion } from 'framer-motion'
import api from '../api/axios'
import Navbar from '../components/Navbar'
import LoadingSpinner from '../components/LoadingSpinner'

function InfoSection({ title, data }) {
  if (!data) return null
  return (
    <div className="bg-white rounded-xl border border-gray-200 p-6 mb-6">
      <h3 className="text-lg font-bold text-gray-800 mb-4">{title}</h3>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {Object.entries(data).map(([key, value]) => {
          if (Array.isArray(value) || (typeof value === 'object' && value !== null)) return null
          return (
            <div key={key} className="flex flex-col">
              <span className="text-xs text-gray-400 uppercase tracking-wide">{key.replace(/_/g, ' ')}</span>
              <span className="text-sm text-gray-700 font-medium mt-0.5">{String(value ?? 'N/A')}</span>
            </div>
          )
        })}
      </div>
    </div>
  )
}

function ListSection({ title, items, labelKey = 'name' }) {
  if (!items || items.length === 0) return null
  return (
    <div className="bg-white rounded-xl border border-gray-200 p-6 mb-6">
      <h3 className="text-lg font-bold text-gray-800 mb-4">{title} ({items.length})</h3>
      <div className="max-h-80 overflow-y-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-gray-500 border-b">
              {Object.keys(items[0] || {}).map((k) => (
                <th key={k} className="pb-2 pr-4 font-medium text-xs uppercase">{k.replace(/_/g, ' ')}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {items.map((item, i) => (
              <tr key={i} className="border-b border-gray-50">
                {Object.values(item).map((v, j) => (
                  <td key={j} className="py-2 pr-4 text-gray-700">{String(v ?? '')}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

export default function AuditDetailPage() {
  const { id } = useParams()
  const [audit, setAudit] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const fetchAudit = async () => {
      try {
        const { data } = await api.get(`/audit/${id}`)
        setAudit(data)
      } catch (err) {
        console.error('Failed to fetch audit', err)
      } finally {
        setLoading(false)
      }
    }
    fetchAudit()
  }, [id])

  const downloadPdf = async () => {
    try {
      const response = await api.get(`/report/${id}`, { responseType: 'blob' })
      const url = window.URL.createObjectURL(new Blob([response.data]))
      const link = document.createElement('a')
      link.href = url
      link.download = `audit_report_${id.slice(0, 8)}.pdf`
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
      window.URL.revokeObjectURL(url)
    } catch {
      alert('Report not available')
    }
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <Navbar />
      <div className="max-w-5xl mx-auto px-6 py-8">
        {loading ? (
          <LoadingSpinner text="Loading audit details..." />
        ) : !audit ? (
          <p className="text-center text-gray-500">Audit not found</p>
        ) : (
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}>
            {/* Header */}
            <div className="flex items-center justify-between mb-8">
              <div>
                <h2 className="text-2xl font-bold text-gray-800">Audit Detail</h2>
                <p className="text-gray-500 text-sm mt-1">
                  {audit.hostname} | {audit.username} | {audit.ip_address}
                </p>
              </div>
              <div className="flex gap-3">
                <button
                  onClick={downloadPdf}
                  className="bg-blue-600 hover:bg-blue-700 text-white font-semibold px-5 py-2.5 rounded-xl text-sm transition shadow"
                >
                  Download PDF
                </button>
              </div>
            </div>

            {/* Status Badge */}
            <div className="bg-white rounded-xl border border-gray-200 p-6 mb-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs text-gray-400 uppercase tracking-wide">Status</p>
                  <span
                    className={`inline-block mt-1 px-3 py-1 rounded-full text-sm font-semibold ${
                      audit.status === 'completed' ? 'bg-green-100 text-green-700' : 'bg-yellow-100 text-yellow-700'
                    }`}
                  >
                    {audit.status}
                  </span>
                </div>
                <div>
                  <p className="text-xs text-gray-400 uppercase tracking-wide">Submitted At</p>
                  <p className="text-sm text-gray-700 mt-1">
                    {audit.submitted_at ? new Date(audit.submitted_at).toLocaleString() : 'N/A'}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-gray-400 uppercase tracking-wide">Token</p>
                  <p className="text-sm text-gray-500 mt-1 font-mono">{audit.verification_token?.slice(0, 16)}...</p>
                </div>
              </div>
            </div>

            <InfoSection title="Operating System" data={audit.system_info} />
            <InfoSection title="Hardware" data={audit.hardware_info} />
            <InfoSection title="Network" data={audit.network_info} />
            <InfoSection title="Security" data={audit.security_info} />
            <InfoSection title="Peripherals" data={audit.peripheral_info} />
            <ListSection title="Installed Software" items={audit.software_entries} />
          </motion.div>
        )}
      </div>
    </div>
  )
}
