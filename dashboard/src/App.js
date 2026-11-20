
import React, { useState, useEffect } from 'react';
import SecurityLogs from './SecurityLogs';
import {
  Container,
  Grid,
  Paper,
  Typography,
  Box,
  Card,
  CardContent,
  Alert,
  CircularProgress,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip
} from '@mui/material';

import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  Title,
  Tooltip,
  Legend,
  ArcElement,
} from 'chart.js';

import { Line, Doughnut } from 'react-chartjs-2';
import axios from 'axios';

// Register Chart.js components
ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  Title,
  Tooltip,
  Legend,
  ArcElement
);

function App() {
  const [dashboardData, setDashboardData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const [mlPredictions, setMlPredictions] = useState([]);
  const [predictionError, setPredictionError] = useState(null);

  // Fetch ML predictions from Flask API
  const fetchMlPredictions = async () => {
    try {
      const response = await axios.get('/api/ml-predictions');
      setMlPredictions(response.data.predictions || []);
      setPredictionError(null);
    } catch (err) {
      setPredictionError('Failed to fetch ML predictions');
      console.error('ML predictions API error:', err);
    }
  };

  
  // Fetch dashboard data and refresh periodically
  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await axios.get('/api/dashboard');
        setDashboardData(response.data);
        setError(null);
      } catch (err) {
        setError('Failed to fetch dashboard data');
        console.error('Dashboard API error:', err);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
    fetchMlPredictions();

    const interval = setInterval(() => {
      fetchData();
      fetchMlPredictions();
    }, 30000);

    return () => clearInterval(interval);
  }, []);
  // Alert distribution chart
  const alertChartData = {
    labels: ['High', 'Medium', 'Low'],
    datasets: [
      {
        data: dashboardData
          ? [
              dashboardData.alerts.high,
              dashboardData.alerts.medium,
              dashboardData.alerts.low
            ]
          : [0, 0, 0],
        backgroundColor: [
          '#f44336',
          '#ff9800',
          '#4caf50'
        ],
        borderWidth: 2,
      },
    ],
  };

  // Log processing timeline
  const logProcessingData = {
    labels: [
      '00:00',
      '04:00',
      '08:00',
      '12:00',
      '16:00',
      '20:00',
      '24:00'
    ],
    datasets: [
      {
        label: 'Sample Log Volume (Illustrative)',
        data: [
          1200,
          1900,
          3000,
          5000,
          4500,
          3200,
          2100
        ],
        borderColor: '#2196f3',
        backgroundColor: 'rgba(33, 150, 243, 0.1)',
        fill: true,
      },
    ],
  };

  // Loading screen
  if (loading) {
    return (
      <Container
        sx={{
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          height: '100vh'
        }}
      >
        <CircularProgress size={60} />
      </Container>
    );
  }

  return (
    <Container maxWidth="xl" sx={{ py: 4 }}>

      {/* Dashboard Heading */}
      <Typography
        variant="h3"
        component="h1"
        gutterBottom
        sx={{ mb: 4, textAlign: 'center' }}
      >
        SIEM Lite Dashboard
      </Typography>

      {/* API Error */}
      {error && (
        <Alert severity="warning" sx={{ mb: 3 }}>
          {error} - Showing mock data for demonstration
        </Alert>
      )}

      <Grid container spacing={3}>

        {/* Statistics Cards */}

        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ bgcolor: '#f3e5f5' }}>
            <CardContent>
              <Typography variant="h6" color="textSecondary">
                Total Alerts
              </Typography>
              <Typography variant="h3" color="primary">
                {dashboardData?.alerts.total || 0}
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ bgcolor: '#e8f5e8' }}>
            <CardContent>
              <Typography variant="h6" color="textSecondary">
               Processing Success Rate
              </Typography>
              <Typography variant="h3" color="success.main">
                {dashboardData?.logs?.success_rate ?? 0}%
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
  <Card sx={{ bgcolor: '#fff3e0' }}>
    <CardContent>
      <Typography variant="h6" color="textSecondary">
        Processing Attempts
      </Typography>
      <Typography variant="h3" color="warning.main">
        {dashboardData?.logs?.total_attempts ?? 0}
      </Typography>
    </CardContent>
  </Card>
</Grid>

        
<Grid item xs={12} sm={6} md={3}>
  <Card sx={{ bgcolor: '#fff3e0' }}>
    <CardContent>
      <Typography variant="h6" color="textSecondary">
        Predicted Threat Events
      </Typography>
      <Typography variant="h3" color="warning.main">
        {dashboardData?.threats?.predicted_threat_events ?? 0}
      </Typography>
    </CardContent>
  </Card>
</Grid>

        {/* Alert Distribution Chart */}

        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Alert Distribution
            </Typography>

            <Box
              sx={{
                height: 300,
                display: 'flex',
                justifyContent: 'center'
              }}
            >
              <Doughnut
                data={alertChartData}
                options={{ maintainAspectRatio: false }}
              />
            </Box>
          </Paper>
        </Grid>

        {/* Log Processing Timeline */}

        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Log Processing Timeline (24h)
            </Typography>

            <Box sx={{ height: 300 }}>
              <Line
                data={logProcessingData}
                options={{ maintainAspectRatio: false }}
              />
            </Box>
          </Paper>
        </Grid>

        {/* Five ML Model Predictions */}

        <Grid item xs={12}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Five ML Model Predictions
            </Typography>

            {predictionError && (
              <Alert severity="warning" sx={{ mb: 2 }}>
                {predictionError}
              </Alert>
            )}

            {mlPredictions.length === 0 ? (
              <Typography color="textSecondary">
                No ML predictions available yet.
              </Typography>
            ) : (
              <TableContainer sx={{ overflowX: 'auto' }}>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>IP Address</TableCell>
                      <TableCell>Timestamp</TableCell>
                      <TableCell>Random Forest</TableCell>
                      <TableCell>XGBoost</TableCell>
                      <TableCell>SVM</TableCell>
                      <TableCell>Logistic Regression</TableCell>
                      <TableCell>Gradient Boosting</TableCell>
                    </TableRow>
                  </TableHead>

                  <TableBody>
                    {mlPredictions.map((prediction) => (
                      <TableRow key={prediction.id}>
                        <TableCell>{prediction.ip}</TableCell>

                                                <TableCell>
                          {prediction.timestamp
                            ? (() => {
                                const parsedDate = new Date(
                                  prediction.timestamp.replace(
                                    /^(\d{2})\/([A-Za-z]{3})\/(\d{4}):/,
                                    '$2 $1, $3 '
                                  )
                                );

                                return isNaN(parsedDate.getTime())
                                  ? prediction.timestamp
                                  : parsedDate.toLocaleString();
                              })()
                            : 'N/A'}
                        </TableCell>
                        {[
                          prediction.random_forest,
                          prediction.xgboost,
                          prediction.svm,
                          prediction.logistic_regression,
                          prediction.gradient_boosting
                        ].map((value, index) => (
                          <TableCell key={index}>
                            <Chip
                              size="small"
                              label={value || 'Unknown'}
                              color={
                                value === 'malicious'
                                  ? 'error'
                                  : value === 'suspicious'
                                  ? 'warning'
                                  : value === 'normal'
                                  ? 'success'
                                  : 'default'
                              }
                            />
                          </TableCell>
                        ))}
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            )}
          </Paper>
        </Grid>

        {/* Recent Alerts */}

        <Grid item xs={12}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Recent Alerts
            </Typography>

            {dashboardData?.alerts.recent?.map((alert) => (
              <Alert
                key={alert.id}
                severity={
                  alert.severity === 'high'
                    ? 'error'
                    : alert.severity === 'medium'
                    ? 'warning'
                    : 'info'
                }
                sx={{ mb: 2 }}
              >
                <Typography variant="body1">
                  {alert.message}
                </Typography>

                <Typography variant="caption" color="textSecondary">
  {alert.created_at
    ? new Date(alert.created_at.replace(' ', 'T') + 'Z').toLocaleString()
    : 'Timestamp unavailable'}
</Typography>
              </Alert>
            ))}
          </Paper>
        </Grid>

            </Grid>

      {/* Security Logs Section */}
      <SecurityLogs />

    </Container>
  );
}

export default App;