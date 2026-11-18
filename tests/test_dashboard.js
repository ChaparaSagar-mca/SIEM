import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import axios from 'axios';
import App from '../dashboard/src/App';

// Mock axios
jest.mock('axios');
const mockedAxios = axios;

// Mock Chart.js to avoid canvas issues in tests
jest.mock('react-chartjs-2', () => ({
  Line: () => <div data-testid="line-chart">Line Chart</div>,
  Bar: () => <div data-testid="bar-chart">Bar Chart</div>,
  Doughnut: () => <div data-testid="doughnut-chart">Doughnut Chart</div>,
}));

describe('SIEM Dashboard', () => {
  beforeEach(() => {
    // Reset mocks
    mockedAxios.get.mockReset();
  });

  test('renders dashboard title', async () => {
    // Mock API response
    mockedAxios.get.mockResolvedValue({
      data: {
        alerts: { total: 127, high: 15, medium: 42, low: 70, recent: [] },
        logs: { processed: 15420, errors: 23, success_rate: 99.85 },
        threats: { blocked: 89, allowed: 15331 },
        system: { cpu: 45, memory: 67, disk: 23, uptime: '15d 7h 23m' }
      }
    });

    render(<App />);
    
    await waitFor(() => {
      expect(screen.getByText('SIEM Lite Dashboard')).toBeInTheDocument();
    });
  });

  test('displays loading state initially', () => {
    mockedAxios.get.mockImplementation(() => new Promise(() => {})); // Never resolves
    
    render(<App />);
    
    expect(screen.getByRole('progressbar')).toBeInTheDocument();
  });

  test('displays error message and mock data on API failure', async () => {
    mockedAxios.get.mockRejectedValue(new Error('API Error'));
    
    render(<App />);
    
    await waitFor(() => {
      expect(screen.getByText(/Failed to fetch dashboard data/)).toBeInTheDocument();
    });
  });

  test('displays dashboard metrics when API succeeds', async () => {
    const mockData = {
      alerts: { total: 127, high: 15, medium: 42, low: 70, recent: [] },
      logs: { processed: 15420, errors: 23, success_rate: 99.85 },
      threats: { blocked: 89, allowed: 15331 },
      system: { cpu: 45, memory: 67, disk: 23, uptime: '15d 7h 23m' }
    };

    mockedAxios.get.mockResolvedValue({ data: mockData });
    
    render(<App />);
    
    await waitFor(() => {
      expect(screen.getByText('127')).toBeInTheDocument(); // Total alerts
      expect(screen.getByText('15,420')).toBeInTheDocument(); // Logs processed
      expect(screen.getByText('89')).toBeInTheDocument(); // Threats blocked
      expect(screen.getByText('99.85%')).toBeInTheDocument(); // Success rate
    });
  });

  test('displays charts', async () => {
    const mockData = {
      alerts: { total: 127, high: 15, medium: 42, low: 70, recent: [] },
      logs: { processed: 15420, errors: 23, success_rate: 99.85 },
      threats: { blocked: 89, allowed: 15331 },
      system: { cpu: 45, memory: 67, disk: 23, uptime: '15d 7h 23m' }
    };

    mockedAxios.get.mockResolvedValue({ data: mockData });
    
    render(<App />);
    
    await waitFor(() => {
      expect(screen.getByTestId('doughnut-chart')).toBeInTheDocument();
      expect(screen.getByTestId('line-chart')).toBeInTheDocument();
    });
  });

  test('displays recent alerts section', async () => {
    const mockData = {
      alerts: { 
        total: 127, 
        high: 15, 
        medium: 42, 
        low: 70, 
        recent: [
          { id: 1, severity: 'high', message: 'Test alert', timestamp: new Date().toISOString() }
        ]
      },
      logs: { processed: 15420, errors: 23, success_rate: 99.85 },
      threats: { blocked: 89, allowed: 15331 },
      system: { cpu: 45, memory: 67, disk: 23, uptime: '15d 7h 23m' }
    };

    mockedAxios.get.mockResolvedValue({ data: mockData });
    
    render(<App />);
    
    await waitFor(() => {
      expect(screen.getByText('Recent Alerts')).toBeInTheDocument();
      expect(screen.getByText('Test alert')).toBeInTheDocument();
    });
  });
});
