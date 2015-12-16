package org.structure;

import java.util.Calendar;
import java.util.TimeZone;
import java.util.concurrent.TimeUnit;

public class Clock 
{
	private Calendar time;
	private int interval;
	
	public Clock(int interval)
	{
		this.interval = interval;
	}
	
	public Clock()
	{
		interval = 60;
	}
	
	public String getTime()
	{
		time = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
		long timeInSeconds = TimeUnit.MILLISECONDS.toSeconds(time.getTimeInMillis());
		return String.valueOf((timeInSeconds/interval));
	}
}
