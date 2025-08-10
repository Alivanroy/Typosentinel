import { useState } from 'react'
import { motion } from 'framer-motion'
import { 
  Users, 
  UserPlus, 
  Settings, 
  Shield,
  Crown,
  Eye,
  Edit,
  Mail,
  Phone,
  Calendar,
  Clock,
  Activity,
  Search,
  MoreVertical,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Lock,
  Unlock,
  UserCheck
} from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/Card'
import { Button } from '../components/ui/Button'

const teamMembers = [
  {
    id: 1,
    name: 'Sarah Johnson',
    email: 'sarah.johnson@company.com',
    role: 'Security Lead',
    permissions: 'admin',
    avatar: 'SJ',
    status: 'active',
    lastActive: '2023-10-20 14:30:00',
    joinDate: '2022-03-15',
    department: 'Security',
    phone: '+1 (555) 123-4567',
    twoFactorEnabled: true,
    sessionsCount: 3,
    vulnerabilitiesFound: 45,
    reportsGenerated: 12
  },
  {
    id: 2,
    name: 'Michael Chen',
    email: 'michael.chen@company.com',
    role: 'DevOps Engineer',
    permissions: 'editor',
    avatar: 'MC',
    status: 'active',
    lastActive: '2023-10-20 13:45:00',
    joinDate: '2022-07-22',
    department: 'Engineering',
    phone: '+1 (555) 234-5678',
    twoFactorEnabled: true,
    sessionsCount: 2,
    vulnerabilitiesFound: 23,
    reportsGenerated: 8
  },
  {
    id: 3,
    name: 'Emily Rodriguez',
    email: 'emily.rodriguez@company.com',
    role: 'Security Analyst',
    permissions: 'viewer',
    avatar: 'ER',
    status: 'active',
    lastActive: '2023-10-20 12:15:00',
    joinDate: '2023-01-10',
    department: 'Security',
    phone: '+1 (555) 345-6789',
    twoFactorEnabled: false,
    sessionsCount: 1,
    vulnerabilitiesFound: 18,
    reportsGenerated: 5
  },
  {
    id: 4,
    name: 'David Kim',
    email: 'david.kim@company.com',
    role: 'Developer',
    permissions: 'viewer',
    avatar: 'DK',
    status: 'inactive',
    lastActive: '2023-10-18 16:20:00',
    joinDate: '2022-11-05',
    department: 'Engineering',
    phone: '+1 (555) 456-7890',
    twoFactorEnabled: true,
    sessionsCount: 0,
    vulnerabilitiesFound: 7,
    reportsGenerated: 2
  },
  {
    id: 5,
    name: 'Lisa Thompson',
    email: 'lisa.thompson@company.com',
    role: 'Compliance Officer',
    permissions: 'editor',
    avatar: 'LT',
    status: 'active',
    lastActive: '2023-10-20 11:30:00',
    joinDate: '2022-05-18',
    department: 'Compliance',
    phone: '+1 (555) 567-8901',
    twoFactorEnabled: true,
    sessionsCount: 1,
    vulnerabilitiesFound: 12,
    reportsGenerated: 15
  }
]

const roles = [
  {
    name: 'Admin',
    permissions: ['Full access', 'User management', 'System configuration', 'All reports'],
    color: 'text-red-600 bg-red-100',
    icon: Crown
  },
  {
    name: 'Editor',
    permissions: ['View and edit', 'Generate reports', 'Manage scans', 'View analytics'],
    color: 'text-blue-600 bg-blue-100',
    icon: Edit
  },
  {
    name: 'Viewer',
    permissions: ['View only', 'Basic reports', 'View vulnerabilities', 'View dashboards'],
    color: 'text-green-600 bg-green-100',
    icon: Eye
  }
]

const recentActivities = [
  {
    id: 1,
    user: 'Sarah Johnson',
    action: 'Generated security report',
    timestamp: '2023-10-20 14:30:00',
    type: 'report'
  },
  {
    id: 2,
    user: 'Michael Chen',
    action: 'Started vulnerability scan',
    timestamp: '2023-10-20 13:45:00',
    type: 'scan'
  },
  {
    id: 3,
    user: 'Emily Rodriguez',
    action: 'Updated vulnerability status',
    timestamp: '2023-10-20 12:15:00',
    type: 'update'
  },
  {
    id: 4,
    user: 'Lisa Thompson',
    action: 'Exported compliance report',
    timestamp: '2023-10-20 11:30:00',
    type: 'export'
  }
]

export function Team() {
  const [searchTerm, setSearchTerm] = useState('')
  const [roleFilter, setRoleFilter] = useState('all')
  const [statusFilter, setStatusFilter] = useState('all')
  const [activeTab, setActiveTab] = useState('members')

  const filteredMembers = teamMembers.filter(member => {
    const matchesSearch = member.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         member.email.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         member.role.toLowerCase().includes(searchTerm.toLowerCase())
    const matchesRole = roleFilter === 'all' || member.permissions === roleFilter
    const matchesStatus = statusFilter === 'all' || member.status === statusFilter
    return matchesSearch && matchesRole && matchesStatus
  })

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'active':
        return <CheckCircle className="w-4 h-4 text-green-500" />
      case 'inactive':
        return <XCircle className="w-4 h-4 text-gray-500" />
      case 'suspended':
        return <AlertTriangle className="w-4 h-4 text-red-500" />
      default:
        return <Clock className="w-4 h-4 text-gray-500" />
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active':
        return 'text-green-700 bg-green-100 border-green-200'
      case 'inactive':
        return 'text-gray-700 bg-gray-100 border-gray-200'
      case 'suspended':
        return 'text-red-700 bg-red-100 border-red-200'
      default:
        return 'text-gray-700 bg-gray-100 border-gray-200'
    }
  }

  const getPermissionIcon = (permission: string) => {
    switch (permission) {
      case 'admin':
        return <Crown className="w-4 h-4 text-red-500" />
      case 'editor':
        return <Edit className="w-4 h-4 text-blue-500" />
      case 'viewer':
        return <Eye className="w-4 h-4 text-green-500" />
      default:
        return <Users className="w-4 h-4 text-gray-500" />
    }
  }

  const getPermissionColor = (permission: string) => {
    switch (permission) {
      case 'admin':
        return 'text-red-700 bg-red-100 border-red-200'
      case 'editor':
        return 'text-blue-700 bg-blue-100 border-blue-200'
      case 'viewer':
        return 'text-green-700 bg-green-100 border-green-200'
      default:
        return 'text-gray-700 bg-gray-100 border-gray-200'
    }
  }

  const activeMembers = teamMembers.filter(m => m.status === 'active').length
  const totalSessions = teamMembers.reduce((sum, m) => sum + m.sessionsCount, 0)

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex flex-col sm:flex-row sm:items-center sm:justify-between"
      >
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Team Management</h1>
          <p className="text-gray-600">
            Manage team members, roles, and permissions
          </p>
        </div>
        <div className="mt-4 sm:mt-0 flex space-x-2">
          <Button variant="outline">
            <Settings className="w-4 h-4 mr-2" />
            Settings
          </Button>
          <Button>
            <UserPlus className="w-4 h-4 mr-2" />
            Invite Member
          </Button>
        </div>
      </motion.div>

      {/* Stats Cards */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="grid grid-cols-1 md:grid-cols-4 gap-4"
      >
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Total Members</p>
                <p className="text-2xl font-bold">{teamMembers.length}</p>
              </div>
              <Users className="w-8 h-8 text-blue-500" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Active Members</p>
                <p className="text-2xl font-bold text-green-600">{activeMembers}</p>
              </div>
              <UserCheck className="w-8 h-8 text-green-500" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Active Sessions</p>
                <p className="text-2xl font-bold text-purple-600">{totalSessions}</p>
              </div>
              <Activity className="w-8 h-8 text-purple-500" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">2FA Enabled</p>
                <p className="text-2xl font-bold text-orange-600">
                  {teamMembers.filter(m => m.twoFactorEnabled).length}
                </p>
              </div>
              <Shield className="w-8 h-8 text-orange-500" />
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Tabs */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
        className="border-b border-gray-200"
      >
        <nav className="-mb-px flex space-x-8">
          <button
            onClick={() => setActiveTab('members')}
            className={`py-2 px-1 border-b-2 font-medium text-sm ${
              activeTab === 'members'
                ? 'border-blue-500 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
            }`}
          >
            <Users className="w-4 h-4 inline mr-2" />
            Team Members
          </button>
          <button
            onClick={() => setActiveTab('roles')}
            className={`py-2 px-1 border-b-2 font-medium text-sm ${
              activeTab === 'roles'
                ? 'border-blue-500 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
            }`}
          >
            <Shield className="w-4 h-4 inline mr-2" />
            Roles & Permissions
          </button>
          <button
            onClick={() => setActiveTab('activity')}
            className={`py-2 px-1 border-b-2 font-medium text-sm ${
              activeTab === 'activity'
                ? 'border-blue-500 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
            }`}
          >
            <Activity className="w-4 h-4 inline mr-2" />
            Recent Activity
          </button>
        </nav>
      </motion.div>

      {activeTab === 'members' && (
        <>
          {/* Filters */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
            className="flex flex-col sm:flex-row gap-4"
          >
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-500" />
              <input
                type="text"
                placeholder="Search team members..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-10 pr-4 py-2 w-full bg-white border border-gray-300 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
            <div className="flex space-x-2">
              <select
                value={roleFilter}
                onChange={(e) => setRoleFilter(e.target.value)}
                className="px-3 py-2 bg-white border border-gray-300 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="all">All Roles</option>
                <option value="admin">Admin</option>
                <option value="editor">Editor</option>
                <option value="viewer">Viewer</option>
              </select>
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="px-3 py-2 bg-white border border-gray-300 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="all">All Status</option>
                <option value="active">Active</option>
                <option value="inactive">Inactive</option>
                <option value="suspended">Suspended</option>
              </select>
            </div>
          </motion.div>

          {/* Team Members List */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.4 }}
            className="space-y-4"
          >
            {filteredMembers.map((member, index) => (
              <motion.div
                key={member.id}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.1 * index }}
              >
                <Card className="hover:shadow-md transition-shadow">
                  <CardContent className="p-6">
                    <div className="flex items-start justify-between">
                      <div className="flex items-start space-x-4">
                        <div className="w-12 h-12 bg-blue-500 rounded-full flex items-center justify-center text-white font-semibold">
                          {member.avatar}
                        </div>
                        <div className="flex-1">
                          <div className="flex items-center space-x-3 mb-2">
                            <h3 className="text-lg font-semibold">{member.name}</h3>
                            <span className={`px-2 py-1 text-xs font-medium rounded-full border ${getStatusColor(member.status)}`}>
                              {getStatusIcon(member.status)}
                              <span className="ml-1">{member.status.toUpperCase()}</span>
                            </span>
                            <span className={`px-2 py-1 text-xs font-medium rounded-full border ${getPermissionColor(member.permissions)}`}>
                              {getPermissionIcon(member.permissions)}
                              <span className="ml-1">{member.permissions.toUpperCase()}</span>
                            </span>
                          </div>
                          <div className="space-y-1 text-sm text-gray-600">
                            <div className="flex items-center space-x-4">
                              <div className="flex items-center">
                                <Mail className="w-4 h-4 mr-1" />
                                {member.email}
                              </div>
                              <div className="flex items-center">
                                <Phone className="w-4 h-4 mr-1" />
                                {member.phone}
                              </div>
                            </div>
                            <div className="flex items-center space-x-4">
                              <div className="flex items-center">
                                <Calendar className="w-4 h-4 mr-1" />
                                Joined {member.joinDate}
                              </div>
                              <div className="flex items-center">
                                <Clock className="w-4 h-4 mr-1" />
                                Last active: {member.lastActive}
                              </div>
                            </div>
                            <div className="flex items-center space-x-4">
                              <span>Department: {member.department}</span>
                              <span>Role: {member.role}</span>
                              <div className="flex items-center">
                                {member.twoFactorEnabled ? (
                                  <Lock className="w-4 h-4 mr-1 text-green-500" />
                                ) : (
                                  <Unlock className="w-4 h-4 mr-1 text-red-500" />
                                )}
                                2FA {member.twoFactorEnabled ? 'Enabled' : 'Disabled'}
                              </div>
                            </div>
                          </div>
                          <div className="grid grid-cols-3 gap-4 mt-3 text-sm">
                            <div>
                              <p className="text-gray-600">Active Sessions</p>
                              <p className="font-medium">{member.sessionsCount}</p>
                            </div>
                            <div>
                              <p className="text-gray-600">Vulnerabilities Found</p>
                              <p className="font-medium">{member.vulnerabilitiesFound}</p>
                            </div>
                            <div>
                              <p className="text-gray-600">Reports Generated</p>
                              <p className="font-medium">{member.reportsGenerated}</p>
                            </div>
                          </div>
                        </div>
                      </div>
                      <div className="flex space-x-2">
                        <Button variant="outline" size="sm">
                          <Edit className="w-4 h-4 mr-1" />
                          Edit
                        </Button>
                        <Button variant="outline" size="sm">
                          <MoreVertical className="w-4 h-4" />
                        </Button>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </motion.div>
            ))}
          </motion.div>
        </>
      )}

      {activeTab === 'roles' && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="grid grid-cols-1 md:grid-cols-3 gap-6"
        >
          {roles.map((role, index) => (
            <motion.div
              key={role.name}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.1 * index }}
            >
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <div className={`w-8 h-8 rounded-full ${role.color} flex items-center justify-center mr-3`}>
                      <role.icon className="w-4 h-4" />
                    </div>
                    {role.name}
                  </CardTitle>
                  <CardDescription>
                    {teamMembers.filter(m => m.permissions === role.name.toLowerCase()).length} members
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    {role.permissions.map((permission, idx) => (
                      <div key={idx} className="flex items-center text-sm">
                        <CheckCircle className="w-3 h-3 text-green-500 mr-2 flex-shrink-0" />
                        {permission}
                      </div>
                    ))}
                  </div>
                  <Button variant="outline" className="w-full mt-4">
                    <Edit className="w-4 h-4 mr-2" />
                    Edit Permissions
                  </Button>
                </CardContent>
              </Card>
            </motion.div>
          ))}
        </motion.div>
      )}

      {activeTab === 'activity' && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="space-y-4"
        >
          {recentActivities.map((activity, index) => (
            <motion.div
              key={activity.id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.1 * index }}
            >
              <Card>
                <CardContent className="p-4">
                  <div className="flex items-center space-x-3">
                    <Activity className="w-5 h-5 text-blue-500" />
                    <div className="flex-1">
                      <p className="font-medium">{activity.user}</p>
                      <p className="text-sm text-gray-600">{activity.action}</p>
                      <p className="text-xs text-gray-400 mt-1">{activity.timestamp}</p>
                    </div>
                    <span className="px-2 py-1 text-xs bg-blue-100 text-blue-700 rounded-md">
                      {activity.type.toUpperCase()}
                    </span>
                  </div>
                </CardContent>
              </Card>
            </motion.div>
          ))}
        </motion.div>
      )}
    </div>
  )
}