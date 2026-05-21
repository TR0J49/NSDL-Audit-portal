import { useNavigate } from 'react-router-dom'

export default function AuditTable({ audits }) {
  const navigate = useNavigate()

  return (
    <div className="overflow-x-auto bg-white rounded-xl shadow-sm border border-gray-200">
      <table className="w-full text-sm">
        <thead>
          <tr className="bg-gray-50 text-left text-gray-600">
            <th className="px-6 py-3 font-semibold">#</th>
            <th className="px-6 py-3 font-semibold">Hostname</th>
            <th className="px-6 py-3 font-semibold">Username</th>
            <th className="px-6 py-3 font-semibold">IP Address</th>
            <th className="px-6 py-3 font-semibold">Status</th>
            <th className="px-6 py-3 font-semibold">Submitted</th>
            <th className="px-6 py-3 font-semibold">Actions</th>
          </tr>
        </thead>
        <tbody>
          {audits.map((audit, i) => (
            <tr key={audit.id} className="border-t border-gray-100 hover:bg-gray-50 transition">
              <td className="px-6 py-4 text-gray-500">{i + 1}</td>
              <td className="px-6 py-4 font-medium text-gray-800">{audit.hostname || '-'}</td>
              <td className="px-6 py-4 text-gray-600">{audit.username || '-'}</td>
              <td className="px-6 py-4 text-gray-600">{audit.ip_address || '-'}</td>
              <td className="px-6 py-4">
                <span
                  className={`inline-block px-3 py-1 rounded-full text-xs font-semibold ${
                    audit.status === 'completed'
                      ? 'bg-green-100 text-green-700'
                      : 'bg-yellow-100 text-yellow-700'
                  }`}
                >
                  {audit.status}
                </span>
              </td>
              <td className="px-6 py-4 text-gray-500">
                {audit.submitted_at ? new Date(audit.submitted_at).toLocaleString() : '-'}
              </td>
              <td className="px-6 py-4">
                <button
                  onClick={() => navigate(`/admin/audit/${audit.id}`)}
                  className="text-blue-600 hover:text-blue-800 font-medium text-xs"
                >
                  View Details
                </button>
              </td>
            </tr>
          ))}
          {audits.length === 0 && (
            <tr>
              <td colSpan={7} className="px-6 py-12 text-center text-gray-400">
                No audits found
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}
