import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import api from '../api/axios'

export default function LoginPage() {
  const navigate = useNavigate()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleLogin = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const { data } = await api.post('/auth/login', { username, password })
      localStorage.setItem('token', data.access_token)
      navigate('/admin/dashboard')
    } catch (err) {
      setError(err.response?.data?.detail || 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-[#0f1b2d] via-[#1a365d] to-[#0f1b2d] flex items-center justify-center p-4">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="bg-white rounded-2xl shadow-2xl w-full max-w-md overflow-hidden"
      >
        <div className="bg-[#1a365d] px-8 py-6 text-center">
          <h1 className="text-xl font-bold text-white">NSDL e-Governance</h1>
          <p className="text-blue-300 text-sm mt-1">System Inspection Platform - Admin</p>
        </div>

        <div className="p-8">
          <h2 className="text-lg font-bold text-gray-800 mb-1">Admin Login</h2>
          <p className="text-gray-500 text-sm mb-6">Sign in to manage inspection reports</p>

          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Username</label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:ring-2 focus:ring-[#1a365d] focus:border-transparent outline-none transition"
                required
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Password</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:ring-2 focus:ring-[#1a365d] focus:border-transparent outline-none transition"
                required
              />
            </div>
            {error && (
              <p className="text-red-500 text-sm text-center bg-red-50 py-2 rounded-lg">{error}</p>
            )}
            <button
              type="submit"
              disabled={loading}
              className="w-full bg-[#1a365d] hover:bg-[#2d4a7a] disabled:bg-gray-400 text-white font-semibold py-3 rounded-xl transition shadow-lg"
            >
              {loading ? 'Signing in...' : 'Sign In'}
            </button>
          </form>
        </div>

        <div className="bg-gray-50 px-8 py-3 border-t border-gray-100">
          <p className="text-xs text-[#800000] text-center">INSPECTION REPORT BY NSDL E-GOVERNANCE</p>
        </div>
      </motion.div>
    </div>
  )
}
