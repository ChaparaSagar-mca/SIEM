
import React, { useEffect, useState, useCallback } from 'react';
import {
  Paper,
  Typography,
  Box,
  TextField,
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  CircularProgress,
  Alert,
  TablePagination,
  InputAdornment
} from '@mui/material';

import {
  Search as SearchIcon,
  Refresh as RefreshIcon
} from '@mui/icons-material';

import axios from 'axios';

function SecurityLogs() {
  const [logs, setLogs] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(20);
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const fetchLogs = useCallback(async () => {
    try {
      setLoading(true);
      setError('');

      const response = await axios.get('/api/logs', {
        params: {
          page: page + 1,
          per_page: rowsPerPage
        }
      });

      setLogs(response.data.logs || []);
      setTotal(response.data.total || 0);
    } catch (err) {
      console.error('Security logs API error:', err);
      setError('Unable to load security logs. Check whether the backend is running.');
    } finally {
      setLoading(false);
    }
  }, [page, rowsPerPage]);

  useEffect(() => {
    fetchLogs();
  }, [fetchLogs]);

  const filteredLogs = logs.filter((log) => {
    const query = search.toLowerCase();

    return (
      String(log.ip || '').toLowerCase().includes(query) ||
      String(log.path || '').toLowerCase().includes(query) ||
      String(log.user_agent || '').toLowerCase().includes(query)
    );
  });

  const getStatusColor = (status) => {
    if (status >= 500) return 'error';
    if (status === 401 || status === 403) return 'warning';
    if (status >= 400) return 'default';
    if (status >= 200 && status < 300) return 'success';
    return 'default';
  };

  return (
    <Box sx={{ mt: 4 }}>
      <Paper sx={{ p: 3 }}>
        <Box
          sx={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: 2,
            mb: 3
          }}
        >
          <Box>
            <Typography variant="h5" fontWeight="bold">
              Security Logs
            </Typography>

            <Typography color="text.secondary">
              Collected activity records from the SIEM database
            </Typography>
          </Box>

          <Chip
            label={`Total Logs: ${total}`}
            color="primary"
            variant="outlined"
          />
        </Box>

        <Box
          sx={{
            display: 'flex',
            gap: 2,
            mb: 3,
            flexWrap: 'wrap'
          }}
        >
          <TextField
            size="small"
            label="Search IP, path or user agent"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            sx={{ flex: 1, minWidth: 230 }}
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <SearchIcon />
                </InputAdornment>
              )
            }}
          />

          <Button
            variant="outlined"
            startIcon={<RefreshIcon />}
            onClick={fetchLogs}
            disabled={loading}
          >
            Refresh
          </Button>
        </Box>

        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        {loading ? (
          <Box sx={{ display: 'flex', justifyContent: 'center', p: 5 }}>
            <CircularProgress />
          </Box>
        ) : (
          <TableContainer sx={{ overflowX: 'auto' }}>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ backgroundColor: '#f5f5f5' }}>
                  <TableCell><strong>Timestamp</strong></TableCell>
                  <TableCell><strong>IP Address</strong></TableCell>
                  <TableCell><strong>Method</strong></TableCell>
                  <TableCell><strong>Requested Path</strong></TableCell>
                  <TableCell><strong>Status</strong></TableCell>
                  <TableCell><strong>User Agent</strong></TableCell>
                </TableRow>
              </TableHead>

              <TableBody>
                {filteredLogs.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={6} align="center">
                      No matching logs found.
                    </TableCell>
                  </TableRow>
                ) : (
                  filteredLogs.map((log) => (
                    <TableRow key={log.id} hover>
                      <TableCell sx={{ minWidth: 170 }}>
                        {log.timestamp}
                      </TableCell>

                      <TableCell>{log.ip}</TableCell>

                      <TableCell>
                        <Chip
                          size="small"
                          label={log.method}
                          variant="outlined"
                        />
                      </TableCell>

                      <TableCell sx={{ minWidth: 160, maxWidth: 260, overflowWrap: 'anywhere' }}>
                        {log.path}
                      </TableCell>

                      <TableCell>
                        <Chip
                          size="small"
                          label={log.status_code}
                          color={getStatusColor(Number(log.status_code))}
                        />
                      </TableCell>

                      <TableCell sx={{ minWidth: 160, maxWidth: 240, overflowWrap: 'anywhere' }}>
                        {log.user_agent || 'Unknown'}
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </TableContainer>
        )}

        <TablePagination
          component="div"
          count={total}
          page={page}
          onPageChange={(event, newPage) => setPage(newPage)}
          rowsPerPage={rowsPerPage}
          onRowsPerPageChange={(event) => {
            setRowsPerPage(parseInt(event.target.value, 10));
            setPage(0);
          }}
          rowsPerPageOptions={[10, 20, 50]}
        />

        <Typography variant="caption" color="text.secondary">
          Search filters the records on the currently loaded page.
        </Typography>
      </Paper>
    </Box>
  );
}

export default SecurityLogs;
