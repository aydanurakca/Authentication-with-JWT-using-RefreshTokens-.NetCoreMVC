using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using JWT_Auth.Entities;
using Microsoft.EntityFrameworkCore;


namespace JWT_Auth.Helpers
{
    public class DataContext : DbContext
    {
        public DbSet<User> Users { get; set; }

        public DataContext(DbContextOptions<DataContext> options) : base(options) { }
    }
}
