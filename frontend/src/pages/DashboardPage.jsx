import { useState, useEffect, useRef, useCallback } from 'react'
import { motion } from 'framer-motion'
import api from '../api/axios'
import Navbar from '../components/Navbar'
import AuditTable from '../components/AuditTable'
import LoadingSpinner from '../components/LoadingSpinner'

export default function DashboardPage() {
  const [audits, setAudits] = useState([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [generating, setGenerating] = useState(false)
  const [newToken, setNewToken] = useState('')
  const [showForm, setShowForm] = useState(false)
  const [branchName, setBranchName] = useState('')
  const [branchCode, setBranchCode] = useState('')
  const [branchOfficer, setBranchOfficer] = useState('')
  const debounceRef = useRef(null)

  const fetchAudits = async () => {
    setLoading(true)
    try {
      const params = {}
      if (search) params.search = search
      if (statusFilter) params.status = statusFilter
      const { data } = await api.get('/audit/list', { params })
      setAudits(data)
    } catch (err) {
      console.error('Failed to fetch audits', err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current)
    debounceRef.current = setTimeout(() => {
      fetchAudits()
    }, search ? 400 : 0)
    return () => clearTimeout(debounceRef.current)
  }, [search, statusFilter])

  const generateToken = async () => {
    setGenerating(true)
    try {
      const params = new URLSearchParams()
      if (branchName) params.append('branch_name', branchName)
      if (branchCode) params.append('branch_code', branchCode)
      if (branchOfficer) params.append('branch_officer', branchOfficer)
      const { data } = await api.post(`/audit/generate-token?${params.toString()}`)
      setNewToken(data.verification_token)
      setShowForm(false)
    } catch (err) {
      console.error('Failed to generate token', err)
    } finally {
      setGenerating(false)
    }
  }

  const verificationUrl = newToken ? `${window.location.origin}/verify/${newToken}` : ''

  return (
    <div className="min-h-screen bg-gray-50">
      <Navbar />
      <div className="max-w-7xl mx-auto px-6 py-8">
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}>
          {/* Header */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-8">
            <div>
              <h2 className="text-2xl font-bold text-gray-800">Inspection Dashboard</h2>
              <p className="text-gray-500 text-sm mt-1">NSDL e-Governance System Inspection Reports</p>
            </div>
            <button
              onClick={() => setShowForm(!showForm)}
              className="bg-[#1a365d] hover:bg-[#2d4a7a] text-white font-semibold px-6 py-3 rounded-xl transition shadow-lg"
            >
              Generate Inspection Link
            </button>
          </div>

          {/* TINFC Form */}
          {showForm && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              className="bg-white border border-gray-200 rounded-xl p-6 mb-6 shadow-sm"
            >
              <h3 className="font-bold text-gray-800 text-sm mb-4">TIN FC Details (Optional)</h3>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-4">
                <div>
                  <label className="block text-xs text-gray-500 mb-1">TIN FC Branch Name</label>
                  <input
                    type="text"
                    value={branchName}
                    onChange={(e) => setBranchName(e.target.value)}
                    placeholder="e.g. RELIGARE BROKING LIMITED"
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 outline-none"
                  />
                </div>
                <div>
                  <label className="block text-xs text-gray-500 mb-1">TIN FC Branch Code</label>
                  <input
                    type="text"
                    value={branchCode}
                    onChange={(e) => setBranchCode(e.target.value)}
                    placeholder="e.g. 8301231"
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 outline-none"
                  />
                </div>
                <div>
                  <label className="block text-xs text-gray-500 mb-1">TIN FC Branch Officer Name</label>
                  <input
                    type="text"
                    value={branchOfficer}
                    onChange={(e) => setBranchOfficer(e.target.value)}
                    placeholder="e.g. SANDIP BALIRAM LOKHANDE"
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 outline-none"
                  />
                </div>
              </div>
              <button
                onClick={generateToken}
                disabled={generating}
                className="bg-[#1a365d] hover:bg-[#2d4a7a] disabled:bg-gray-400 text-white font-semibold px-6 py-2.5 rounded-lg text-sm transition"
              >
                {generating ? 'Generating...' : 'Generate Link'}
              </button>
            </motion.div>
          )}

          {/* Generated Token */}
          {newToken && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              className="bg-green-50 border border-green-200 rounded-xl p-5 mb-6"
            >
              <h3 className="font-semibold text-green-800 text-sm mb-2">Inspection Link Generated</h3>
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  readOnly
                  value={verificationUrl}
                  className="flex-1 bg-white border border-green-300 rounded-lg px-4 py-2 text-sm text-gray-700"
                />
                <button
                  onClick={() => navigator.clipboard.writeText(verificationUrl)}
                  className="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-lg text-sm font-medium transition"
                >
                  Copy
                </button>
              </div>
              <p className="text-xs text-green-600 mt-2">Send this link to the TIN FC for system inspection.</p>
            </motion.div>
          )}

          {/* Filters */}
          <div className="flex flex-col sm:flex-row gap-3 mb-6">
            <input
              type="text"
              placeholder="Search by hostname or username..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="flex-1 px-4 py-3 border border-gray-300 rounded-xl focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none text-sm"
            />
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="px-4 py-3 border border-gray-300 rounded-xl focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none text-sm bg-white"
            >
              <option value="">All Status</option>
              <option value="pending">Pending</option>
              <option value="completed">Completed</option>
            </select>
            <button
              onClick={fetchAudits}
              className="px-6 py-3 bg-gray-100 hover:bg-gray-200 text-gray-700 rounded-xl text-sm font-medium transition"
            >
              Refresh
            </button>
          </div>

          {/* Stats */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-6">
            <div className="bg-white rounded-xl p-5 border border-gray-200">
              <p className="text-sm text-gray-500">Total Inspections</p>
              <p className="text-2xl font-bold text-gray-800 mt-1">{audits.length}</p>
            </div>
            <div className="bg-white rounded-xl p-5 border border-gray-200">
              <p className="text-sm text-gray-500">Completed</p>
              <p className="text-2xl font-bold text-green-600 mt-1">
                {audits.filter((a) => a.status === 'completed').length}
              </p>
            </div>
            <div className="bg-white rounded-xl p-5 border border-gray-200">
              <p className="text-sm text-gray-500">Pending</p>
              <p className="text-2xl font-bold text-yellow-600 mt-1">
                {audits.filter((a) => a.status === 'pending').length}
              </p>
            </div>
          </div>

          {/* Table */}
          {loading ? <LoadingSpinner text="Loading inspections..." /> : <AuditTable audits={audits} />}
        </motion.div>
      </div>
    </div>
  )
}
