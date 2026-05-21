import { useNavigate } from 'react-router-dom'

export default function Navbar() {
  const navigate = useNavigate()

  const logout = () => {
    localStorage.removeItem('token')
    navigate('/admin/login')
  }

  return (
    <nav className="bg-[#1a365d] px-6 py-4 flex items-center justify-between shadow-lg">
      <div className="flex items-center gap-3">
        <div className="w-8 h-8 bg-white/20 rounded-lg flex items-center justify-center">
          <span className="text-white font-bold text-sm">NE</span>
        </div>
        <div>
          <h1 className="text-sm font-bold text-white">NSDL e-Governance</h1>
          <p className="text-xs text-blue-300">System Inspection Platform</p>
        </div>
      </div>
      <div className="flex items-center gap-4">
        <button
          onClick={() => navigate('/admin/dashboard')}
          className="text-sm text-blue-200 hover:text-white transition"
        >
          Dashboard
        </button>
        <button
          onClick={logout}
          className="text-sm bg-white/10 text-white px-4 py-2 rounded-lg hover:bg-white/20 transition"
        >
          Logout
        </button>
      </div>
    </nav>
  )
}
