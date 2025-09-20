import React, { useState, useEffect, createContext, useContext } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, useNavigate } from 'react-router-dom';
import axios from 'axios';
import { Button } from './components/ui/button';
import { Input } from './components/ui/input';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './components/ui/card';
import { Label } from './components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './components/ui/select';
import { Badge } from './components/ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './components/ui/table';
import { toast } from 'sonner';
import { Toaster } from './components/ui/sonner';
import { Moon, Sun, LogOut, CreditCard, History, FileText, Users, DollarSign, Settings } from 'lucide-react';
import './App.css';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

// Theme Context
const ThemeContext = createContext();

const useTheme = () => {
  const context = useContext(ThemeContext);
  if (!context) {
    throw new Error('useTheme must be used within a ThemeProvider');
  }
  return context;
};

const ThemeProvider = ({ children }) => {
  const [theme, setTheme] = useState('light');

  useEffect(() => {
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme) {
      setTheme(savedTheme);
    } else if (window.matchMedia('(prefers-color-scheme: dark)').matches) {
      setTheme('dark');
    }
  }, []);

  useEffect(() => {
    localStorage.setItem('theme', theme);
    if (theme === 'dark') {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }, [theme]);

  const toggleTheme = () => {
    setTheme(prev => prev === 'light' ? 'dark' : 'light');
  };

  return (
    <ThemeContext.Provider value={{ theme, toggleTheme }}>
      {children}
    </ThemeContext.Provider>
  );
};

// Auth Context
const AuthContext = createContext();

const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (token) {
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
      fetchUser();
    } else {
      setLoading(false);
    }
  }, []);

  const fetchUser = async () => {
    try {
      const response = await axios.get(`${API}/me`);
      setUser(response.data);
    } catch (error) {
      localStorage.removeItem('token');
      delete axios.defaults.headers.common['Authorization'];
    } finally {
      setLoading(false);
    }
  };

  const login = async (identifier, password) => {
    try {
      const response = await axios.post(`${API}/login`, {
        identifier,
        password
      });

      const { access_token, user: userData } = response.data;
      localStorage.setItem('token', access_token);
      axios.defaults.headers.common['Authorization'] = `Bearer ${access_token}`;
      setUser(userData);
      
      toast.success('Login successful!');
      return userData;
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Login failed');
      throw error;
    }
  };

  const register = async (userData) => {
    try {
      await axios.post(`${API}/register`, userData);
      toast.success('Registration successful! Please login.');
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Registration failed');
      throw error;
    }
  };

  const logout = () => {
    localStorage.removeItem('token');
    delete axios.defaults.headers.common['Authorization'];
    setUser(null);
    toast.success('Logged out successfully');
  };

  return (
    <AuthContext.Provider value={{ user, login, register, logout, loading }}>
      {children}
    </AuthContext.Provider>
  );
};

// Components
const ThemeToggle = () => {
  const { theme, toggleTheme } = useTheme();
  
  return (
    <Button 
      variant="ghost" 
      size="icon" 
      onClick={toggleTheme}
      className="fixed top-4 right-4 z-50"
    >
      {theme === 'light' ? <Moon className="h-5 w-5" /> : <Sun className="h-5 w-5" />}
    </Button>
  );
};

// Student Login Page
const StudentLoginPage = () => {
  const [identifier, setIdentifier] = useState('');
  const [password, setPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);

    try {
      const userData = await login(identifier, password);
      if (userData.role === 'student') {
        navigate('/student-dashboard');
      } else {
        toast.error('Please use admin login for administrative access');
      }
    } catch (error) {
      // Error already handled in login function
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-indigo-100 dark:from-gray-900 dark:to-gray-800 p-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <div className="mx-auto w-20 h-20 bg-indigo-600 rounded-xl flex items-center justify-center mb-4">
            <span className="text-2xl font-bold text-white">NAITS</span>
          </div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Student Portal</h1>
          <p className="text-gray-600 dark:text-gray-400 mt-2">
            National Association of Information Technology Students
          </p>
        </div>

        <Card className="shadow-xl border-0 bg-white/80 dark:bg-gray-800/80 backdrop-blur-sm">
          <CardHeader className="space-y-1">
            <CardTitle className="text-2xl text-center">Student Sign In</CardTitle>
            <CardDescription className="text-center">
              Enter your Student ID and password
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="identifier">Student ID</Label>
                <Input
                  id="identifier"
                  type="text"
                  placeholder="IMT/21U/1234"
                  value={identifier}
                  onChange={(e) => setIdentifier(e.target.value)}
                  required
                  className="h-11"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="password">Password</Label>
                <Input
                  id="password"
                  type="password"
                  placeholder="Enter your password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  className="h-11"
                />
              </div>
              <Button 
                type="submit" 
                className="w-full h-11 bg-indigo-600 hover:bg-indigo-700" 
                disabled={isLoading}
              >
                {isLoading ? 'Signing In...' : 'Sign In as Student'}
              </Button>
            </form>
            
            <div className="mt-6 text-center space-y-3">
              <p className="text-sm text-gray-600 dark:text-gray-400">
                New student?{' '}
                <Button 
                  variant="link" 
                  className="p-0 h-auto text-indigo-600 hover:text-indigo-700"
                  onClick={() => navigate('/register')}
                >
                  Register here
                </Button>
              </p>
              
              <div className="flex items-center justify-center">
                <div className="border-t border-gray-300 dark:border-gray-600 flex-1"></div>
                <span className="px-3 text-sm text-gray-500 dark:text-gray-400">or</span>
                <div className="border-t border-gray-300 dark:border-gray-600 flex-1"></div>
              </div>
              
              <Button 
                variant="outline" 
                className="w-full"
                onClick={() => navigate('/admin-login')}
              >
                Admin Login
              </Button>
            </div>

            <div className="mt-6 p-4 bg-gray-50 dark:bg-gray-700 rounded-lg">
              <p className="text-xs text-gray-600 dark:text-gray-400 mb-2">Demo Student:</p>
              <p className="text-xs text-gray-500 dark:text-gray-400">
                ID: <code>IMT/21U/1234</code> | Password: <code>password</code>
              </p>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

// Admin Login Page
const AdminLoginPage = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);

    try {
      const userData = await login(username, password);
      if (userData.role === 'admin') {
        navigate('/admin-dashboard');
      } else {
        toast.error('Please use student login for student access');
      }
    } catch (error) {
      // Error already handled in login function
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-50 to-gray-100 dark:from-gray-900 dark:to-gray-800 p-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <div className="mx-auto w-20 h-20 bg-slate-700 rounded-xl flex items-center justify-center mb-4">
            <span className="text-2xl font-bold text-white">NAITS</span>
          </div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Admin Portal</h1>
          <p className="text-gray-600 dark:text-gray-400 mt-2">
            Administrative Dashboard Access
          </p>
        </div>

        <Card className="shadow-xl border-0 bg-white/80 dark:bg-gray-800/80 backdrop-blur-sm">
          <CardHeader className="space-y-1">
            <CardTitle className="text-2xl text-center">Admin Sign In</CardTitle>
            <CardDescription className="text-center">
              Enter your administrative credentials
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="username">Username</Label>
                <Input
                  id="username"
                  type="text"
                  placeholder="admin"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  required
                  className="h-11"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="password">Password</Label>
                <Input
                  id="password"
                  type="password"
                  placeholder="Enter admin password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  className="h-11"
                />
              </div>
              <Button 
                type="submit" 
                className="w-full h-11 bg-slate-700 hover:bg-slate-800" 
                disabled={isLoading}
              >
                {isLoading ? 'Signing In...' : 'Sign In as Admin'}
              </Button>
            </form>
            
            <div className="mt-6 text-center">
              <div className="flex items-center justify-center">
                <div className="border-t border-gray-300 dark:border-gray-600 flex-1"></div>
                <span className="px-3 text-sm text-gray-500 dark:text-gray-400">or</span>
                <div className="border-t border-gray-300 dark:border-gray-600 flex-1"></div>
              </div>
              
              <Button 
                variant="outline" 
                className="w-full mt-3"
                onClick={() => navigate('/')}
              >
                Student Login
              </Button>
            </div>

            <div className="mt-6 p-4 bg-gray-50 dark:bg-gray-700 rounded-lg">
              <p className="text-xs text-gray-600 dark:text-gray-400 mb-2">Demo Admin:</p>
              <p className="text-xs text-gray-500 dark:text-gray-400">
                Username: <code>admin</code> | Password: <code>admin123</code>
              </p>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

const RegisterPage = () => {
  const [formData, setFormData] = useState({
    role: 'student',
    student_id: '',
    email: '',
    username: '',
    password: '',
    department: '',
    level: ''
  });
  const [isLoading, setIsLoading] = useState(false);
  const { register } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);

    try {
      await register(formData);
      navigate('/');
    } catch (error) {
      // Error already handled in register function
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-indigo-100 dark:from-gray-900 dark:to-gray-800 p-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <div className="mx-auto w-20 h-20 bg-indigo-600 rounded-xl flex items-center justify-center mb-4">
            <span className="text-2xl font-bold text-white">NAITS</span>
          </div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Register</h1>
        </div>

        <Card className="shadow-xl border-0 bg-white/80 dark:bg-gray-800/80 backdrop-blur-sm">
          <CardHeader>
            <CardTitle className="text-2xl text-center">Create Account</CardTitle>
            <CardDescription className="text-center">
              Register as a new student
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="student_id">Student ID</Label>
                <Input
                  id="student_id"
                  type="text"
                  placeholder="IMT/21U/1234"
                  value={formData.student_id}
                  onChange={(e) => setFormData({...formData, student_id: e.target.value})}
                  required
                />
              </div>
              
              <div className="space-y-2">
                <Label htmlFor="email">Student Email</Label>
                <Input
                  id="email"
                  type="email"
                  placeholder="21u1234@students.mau.edu.ng"
                  value={formData.email}
                  onChange={(e) => setFormData({...formData, email: e.target.value})}
                  required
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="department">Department</Label>
                <Select value={formData.department} onValueChange={(value) => setFormData({...formData, department: value})}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select department" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="computer-science">Computer Science</SelectItem>
                    <SelectItem value="information-technology">Information Technology</SelectItem>
                    <SelectItem value="software-engineering">Software Engineering</SelectItem>
                    <SelectItem value="cybersecurity">Cybersecurity</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label htmlFor="level">Level</Label>
                <Select value={formData.level} onValueChange={(value) => setFormData({...formData, level: value})}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select level" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="100">100 Level</SelectItem>
                    <SelectItem value="200">200 Level</SelectItem>
                    <SelectItem value="300">300 Level</SelectItem>
                    <SelectItem value="400">400 Level</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label htmlFor="password">Password</Label>
                <Input
                  id="password"
                  type="password"
                  placeholder="Enter your password"
                  value={formData.password}
                  onChange={(e) => setFormData({...formData, password: e.target.value})}
                  required
                />
              </div>

              <Button 
                type="submit" 
                className="w-full bg-indigo-600 hover:bg-indigo-700" 
                disabled={isLoading}
              >
                {isLoading ? 'Creating Account...' : 'Register'}
              </Button>
            </form>
            
            <div className="mt-6 text-center">
              <p className="text-sm text-gray-600 dark:text-gray-400">
                Already have an account?{' '}
                <Button 
                  variant="link" 
                  className="p-0 h-auto text-indigo-600 hover:text-indigo-700"
                  onClick={() => navigate('/')}
                >
                  Sign in here
                </Button>
              </p>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

const StudentDashboard = () => {
  const { user, logout } = useAuth();
  const [payments, setPayments] = useState([]);
  const [newPayment, setNewPayment] = useState({ fee_type: 'membership', amount: 5000 });
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    fetchPaymentHistory();
  }, []);

  const fetchPaymentHistory = async () => {
    try {
      const response = await axios.get(`${API}/payments/history`);
      setPayments(response.data);
    } catch (error) {
      toast.error('Failed to fetch payment history');
    }
  };

  const handlePayment = async (e) => {
    e.preventDefault();
    setIsLoading(true);

    try {
      await axios.post(`${API}/payments/create`, newPayment);
      toast.success('Payment processed successfully!');
      fetchPaymentHistory();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Payment failed');
    } finally {
      setIsLoading(false);
    }
  };

  const downloadReceipt = async (paymentId) => {
    try {
      const response = await axios.get(`${API}/payments/${paymentId}/receipt`);
      toast.success('Receipt downloaded!');
      // In a real app, this would generate and download a PDF
      console.log('Receipt data:', response.data);
    } catch (error) {
      toast.error('Failed to download receipt');
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      <header className="bg-white dark:bg-gray-800 shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center space-x-4">
              <div className="w-10 h-10 bg-indigo-600 rounded-lg flex items-center justify-center">
                <span className="text-sm font-bold text-white">NAITS</span>
              </div>
              <div>
                <h1 className="text-xl font-semibold text-gray-900 dark:text-white">Student Dashboard</h1>
                <p className="text-sm text-gray-500 dark:text-gray-400">Welcome, {user?.student_id}</p>
              </div>
            </div>
            <Button variant="ghost" onClick={logout} className="text-red-600 hover:text-red-700">
              <LogOut className="h-4 w-4 mr-2" />
              Logout
            </Button>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Make Payment */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <CreditCard className="h-5 w-5 mr-2" />
                Make Payment
              </CardTitle>
            </CardHeader>
            <CardContent>
              <form onSubmit={handlePayment} className="space-y-4">
                <div className="space-y-2">
                  <Label>Fee Type</Label>
                  <Select 
                    value={newPayment.fee_type} 
                    onValueChange={(value) => setNewPayment({...newPayment, fee_type: value})}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="membership">Membership Dues</SelectItem>
                      <SelectItem value="event">Event Fee</SelectItem>
                      <SelectItem value="exam">Exam Fee</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                
                <div className="space-y-2">
                  <Label>Amount (NGN)</Label>
                  <Input
                    type="number"
                    value={newPayment.amount}
                    onChange={(e) => setNewPayment({...newPayment, amount: parseFloat(e.target.value)})}
                    min="100"
                    required
                  />
                </div>

                <Button 
                  type="submit" 
                  className="w-full bg-indigo-600 hover:bg-indigo-700" 
                  disabled={isLoading}
                >
                  {isLoading ? 'Processing...' : 'Pay Now'}
                </Button>
              </form>
            </CardContent>
          </Card>

          {/* Payment History */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <History className="h-5 w-5 mr-2" />
                Payment History
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {payments.length === 0 ? (
                  <p className="text-center text-gray-500 py-8">No payments yet</p>
                ) : (
                  payments.map((payment) => (
                    <div key={payment.id} className="flex items-center justify-between p-4 border rounded-lg">
                      <div>
                        <p className="font-medium capitalize">{payment.fee_type}</p>
                        <p className="text-sm text-gray-500">
                          ₦{payment.amount} • {new Date(payment.created_at).toLocaleDateString()}
                        </p>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Badge 
                          variant={payment.status === 'completed' ? 'default' : 'secondary'}
                          className={payment.status === 'completed' ? 'bg-green-100 text-green-800' : ''}
                        >
                          {payment.status}
                        </Badge>
                        {payment.status === 'completed' && (
                          <Button 
                            size="sm" 
                            variant="outline"
                            onClick={() => downloadReceipt(payment.id)}
                          >
                            <FileText className="h-4 w-4 mr-1" />
                            Receipt
                          </Button>
                        )}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </CardContent>
          </Card>
        </div>
      </main>
    </div>
  );
};

const AdminDashboard = () => {
  const { logout } = useAuth();
  const [payments, setPayments] = useState([]);
  const [stats, setStats] = useState({ total_revenue: 0, total_count: 0 });

  useEffect(() => {
    fetchAllPayments();
  }, []);

  const fetchAllPayments = async () => {
    try {
      const response = await axios.get(`${API}/admin/payments`);
      setPayments(response.data.payments);
      setStats({
        total_revenue: response.data.total_revenue,
        total_count: response.data.total_count
      });
    } catch (error) {
      toast.error('Failed to fetch payments');
    }
  };

  const updatePaymentStatus = async (paymentId, status) => {
    try {
      await axios.put(`${API}/admin/payments/${paymentId}/status?status=${status}`);
      toast.success('Payment status updated');
      fetchAllPayments();
    } catch (error) {
      toast.error('Failed to update payment status');
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      <header className="bg-white dark:bg-gray-800 shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center space-x-4">
              <div className="w-10 h-10 bg-indigo-600 rounded-lg flex items-center justify-center">
                <span className="text-sm font-bold text-white">NAITS</span>
              </div>
              <div>
                <h1 className="text-xl font-semibold text-gray-900 dark:text-white">Admin Dashboard</h1>
                <p className="text-sm text-gray-500 dark:text-gray-400">Payment Management System</p>
              </div>
            </div>
            <Button variant="ghost" onClick={logout} className="text-red-600 hover:text-red-700">
              <LogOut className="h-4 w-4 mr-2" />
              Logout
            </Button>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center">
                <DollarSign className="h-8 w-8 text-green-600" />
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-500">Total Revenue</p>
                  <p className="text-2xl font-bold text-gray-900 dark:text-white">₦{stats.total_revenue.toLocaleString()}</p>
                </div>
              </div>
            </CardContent>
          </Card>
          
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center">
                <CreditCard className="h-8 w-8 text-blue-600" />
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-500">Total Payments</p>
                  <p className="text-2xl font-bold text-gray-900 dark:text-white">{stats.total_count}</p>
                </div>
              </div>
            </CardContent>
          </Card>
          
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center">
                <Users className="h-8 w-8 text-purple-600" />
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-500">Active Students</p>
                  <p className="text-2xl font-bold text-gray-900 dark:text-white">{new Set(payments.map(p => p.user_id)).size}</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Payments Table */}
        <Card>
          <CardHeader>
            <CardTitle>All Payments</CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Student ID</TableHead>
                  <TableHead>Fee Type</TableHead>
                  <TableHead>Amount</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Date</TableHead>
                  <TableHead>Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {payments.map((payment) => (
                  <TableRow key={payment.id}>
                    <TableCell className="font-medium">{payment.user_id.substring(0, 8)}...</TableCell>
                    <TableCell className="capitalize">{payment.fee_type}</TableCell>
                    <TableCell>₦{payment.amount}</TableCell>
                    <TableCell>
                      <Badge 
                        variant={payment.status === 'completed' ? 'default' : 'secondary'}
                        className={payment.status === 'completed' ? 'bg-green-100 text-green-800' : ''}
                      >
                        {payment.status}
                      </Badge>
                    </TableCell>
                    <TableCell>{new Date(payment.created_at).toLocaleDateString()}</TableCell>
                    <TableCell>
                      <Select 
                        value={payment.status} 
                        onValueChange={(value) => updatePaymentStatus(payment.id, value)}
                      >
                        <SelectTrigger className="w-32">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="pending">Pending</SelectItem>
                          <SelectItem value="completed">Completed</SelectItem>
                          <SelectItem value="failed">Failed</SelectItem>
                          <SelectItem value="disputed">Disputed</SelectItem>
                          <SelectItem value="refunded">Refunded</SelectItem>
                        </SelectContent>
                      </Select>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            {payments.length === 0 && (
              <p className="text-center text-gray-500 py-8">No payments found</p>
            )}
          </CardContent>
        </Card>
      </main>
    </div>
  );
};

// Protected Route Component
const ProtectedRoute = ({ children, allowedRoles }) => {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-indigo-600"></div>
      </div>
    );
  }

  if (!user) {
    return <Navigate to="/" replace />;
  }

  if (allowedRoles && !allowedRoles.includes(user.role)) {
    return <Navigate to="/" replace />;
  }

  return children;
};

function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <div className="App">
          <Router>
            <ThemeToggle />
            <Routes>
              <Route path="/" element={<StudentLoginPage />} />
              <Route path="/admin-login" element={<AdminLoginPage />} />
              <Route path="/register" element={<RegisterPage />} />
              <Route 
                path="/student-dashboard" 
                element={
                  <ProtectedRoute allowedRoles={['student']}>
                    <StudentDashboard />
                  </ProtectedRoute>
                } 
              />
              <Route 
                path="/admin-dashboard" 
                element={
                  <ProtectedRoute allowedRoles={['admin']}>
                    <AdminDashboard />
                  </ProtectedRoute>
                } 
              />
            </Routes>
          </Router>
          <Toaster position="top-right" />
        </div>
      </AuthProvider>
    </ThemeProvider>
  );
}

export default App;